<?php

namespace App\Infrastructure\OAuth;

use DateTimeImmutable;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;
use Throwable;

final readonly class PrivateKeyJwtClientAuthenticator
{
    public function __construct(
        private ChatGptClientMetadata $metadata,
        private ClientProfileRegistry $profiles,
        private ClientAssertionReplayStore $replays,
    ) {}

    /** @param list<string> $allowedAudiences */
    public function validate(ServerRequestInterface $request, array $allowedAudiences): string
    {
        $stage = 'client_auth_method';
        try {
            $parameters = (array) $request->getParsedBody();
            // Do not log a supplied assertion, header, client secret or token.
            $authorization = trim($request->getHeaderLine('Authorization'));
            if (array_key_exists('client_secret', $parameters)
                || ($authorization !== '' && preg_match('/^Bearer\\s+\\S+$/iD', $authorization) !== 1)) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'conflicting_authentication_methods');
            }

            $clientId = $this->boundedString($parameters, 'client_id', 1024);
            $assertionType = $this->boundedString($parameters, 'client_assertion_type', 256);
            $assertion = $this->boundedString($parameters, 'client_assertion', 16384);

            $stage = 'client_profile';
            $profile = $this->profiles->active($clientId);
            if ($profile === null) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'client_profile_unavailable');
            }
            if ($assertionType !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' || $assertion === '') {
                throw OAuthClientAuthDiagnostic::invalidClient($request, 'client_assertion', 'assertion_missing_or_invalid_type');
            }

            $stage = 'jwt_header';
            try {
                $unverifiedHeaders = $this->assertionHeaders($assertion);
            } catch (Throwable $exception) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'malformed_assertion_header', $exception);
            }
            try {
                $keyId = $this->validateUnverifiedHeaders($unverifiedHeaders);
            } catch (Throwable $exception) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'unsupported_assertion_header', $exception);
            }

            $stage = 'jwks_resolution';
            $jwks = $profile['strategy'] === 'cimd_private_key_jwt'
                ? $this->metadata->jwksForKeyId($keyId)
                : $profile['jwks'];
            if (! $this->containsKeyId($jwks, $keyId)) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'assertion_key_id_unavailable');
            }

            $stage = 'jwt_signature';
            try {
                [$claims, $headers] = $this->decodeWithJwks($assertion, $jwks);
            } catch (SignatureInvalidException $exception) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'assertion_signature_invalid', $exception);
            } catch (ExpiredException|BeforeValidException $exception) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, 'jwt_time', 'assertion_time_invalid', $exception);
            } catch (Throwable $exception) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'assertion_verification_failed', $exception);
            }

            $stage = 'jwt_claims';
            $this->validateHeaders($request, $headers, $keyId);
            $this->validateClaims($request, $claims, $clientId, $allowedAudiences);

            $stage = 'jwt_replay';
            $jti = (string) $claims->jti;
            $expiresAt = (new DateTimeImmutable)->setTimestamp((int) $claims->exp);
            if (! $this->replays->remember($clientId, $jti, $expiresAt)) {
                throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'assertion_replayed');
            }

            return $clientId;
        } catch (OAuthClientMetadataUnavailable $exception) {
            OAuthClientAuthDiagnostic::remember($stage, 'metadata_temporarily_unavailable', $exception);
            throw $exception;
        } catch (OAuthServerException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw OAuthClientAuthDiagnostic::invalidClient($request, $stage, 'unexpected_authentication_failure', $exception);
        }
    }

    /** @param array<string,mixed> $jwks */
    private function containsKeyId(array $jwks, string $keyId): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (is_array($key) && ($key['kid'] ?? null) === $keyId) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, mixed> $jwks
     * @return array{0: stdClass, 1: stdClass}
     */
    private function decodeWithJwks(string $assertion, array $jwks): array
    {
        $headers = new stdClass;
        $claims = JWT::decode($assertion, JWK::parseKeySet($jwks), $headers);

        return [$claims, $headers];
    }

    /** @return array<string, mixed> */
    private function assertionHeaders(string $assertion): array
    {
        $parts = explode('.', $assertion);
        if (count($parts) !== 3 || $parts[0] === '') {
            throw new \UnexpectedValueException('Invalid client assertion format.');
        }

        $decoded = json_decode(JWT::urlsafeB64Decode($parts[0]), true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($decoded)) {
            throw new \UnexpectedValueException('Invalid client assertion header.');
        }

        return $decoded;
    }

    /** @param array<string, mixed> $headers */
    private function validateUnverifiedHeaders(array $headers): string
    {
        $keyId = $headers['kid'] ?? null;
        if (($headers['alg'] ?? null) !== 'RS256'
            || ! is_string($keyId)
            || $keyId === ''
            || strlen($keyId) > 256) {
            throw new \UnexpectedValueException('Invalid client assertion header.');
        }

        return $keyId;
    }

    private function validateHeaders(ServerRequestInterface $request, stdClass $headers, string $expectedKeyId): void
    {
        if (($headers->alg ?? null) !== 'RS256'
            || ! is_string($headers->kid ?? null)
            || ! hash_equals($expectedKeyId, (string) $headers->kid)) {
            throw OAuthClientAuthDiagnostic::invalidClient($request, 'jwt_header', 'verified_header_mismatch');
        }
    }

    /** @param list<string> $allowedAudiences */
    private function validateClaims(ServerRequestInterface $request, stdClass $claims, string $clientId, array $allowedAudiences): void
    {
        $issuer = $claims->iss ?? null;
        $subject = $claims->sub ?? null;
        $jti = $claims->jti ?? null;
        $issuedAt = $claims->iat ?? null;
        $expiresAt = $claims->exp ?? null;

        if ($issuer !== $clientId || $subject !== $clientId
            || ! is_string($jti) || $jti === '' || strlen($jti) > 256
            || ! is_numeric($issuedAt) || ! is_numeric($expiresAt)) {
            throw OAuthClientAuthDiagnostic::invalidClient($request, 'jwt_claims', 'assertion_claims_invalid');
        }

        $issuedAt = (int) $issuedAt;
        $expiresAt = (int) $expiresAt;
        $now = time();
        $maxLifetime = max(60, (int) config('oauth.ttl.client_assertion_seconds'));

        if ($expiresAt <= $issuedAt
            || ($expiresAt - $issuedAt) > $maxLifetime
            || $issuedAt < ($now - $maxLifetime)
            || $expiresAt > ($now + $maxLifetime)) {
            throw OAuthClientAuthDiagnostic::invalidClient($request, 'jwt_time', 'assertion_lifetime_invalid');
        }

        $audiences = $claims->aud ?? null;
        if (is_string($audiences)) {
            $audiences = [$audiences];
        }
        if (! is_array($audiences) || array_intersect($allowedAudiences, $audiences) === []) {
            throw OAuthClientAuthDiagnostic::invalidClient($request, 'jwt_audience', 'assertion_audience_invalid');
        }
    }

    /** @param array<string, mixed> $parameters */
    private function boundedString(array $parameters, string $key, int $maxLength): string
    {
        $value = $parameters[$key] ?? null;

        return is_string($value) && strlen($value) <= $maxLength ? $value : '';
    }
}
