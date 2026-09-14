<?php

namespace App\Infrastructure\OAuth;

use DateTimeImmutable;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;
use Throwable;

final readonly class PrivateKeyJwtClientAuthenticator
{
    public function __construct(
        private ChatGptClientMetadata $metadata,
        private ClientAssertionReplayStore $replays,
    ) {}

    /** @param list<string> $allowedAudiences */
    public function validate(ServerRequestInterface $request, array $allowedAudiences): string
    {
        try {
            $parameters = (array) $request->getParsedBody();
            $clientId = $this->boundedString($parameters, 'client_id', 1024);
            $assertionType = $this->boundedString($parameters, 'client_assertion_type', 256);
            $assertion = $this->boundedString($parameters, 'client_assertion', 16384);

            if ($clientId !== (string) config('oauth.client.id')
                || $assertionType !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                || $assertion === '') {
                throw OAuthServerException::invalidClient($request);
            }

            $unverifiedHeaders = $this->assertionHeaders($assertion);
            $keyId = $this->validateUnverifiedHeaders($unverifiedHeaders);
            [$claims, $headers] = $this->decodeWithJwks(
                $assertion,
                $this->metadata->jwksForKeyId($keyId),
            );
            $this->validateHeaders($headers, $keyId);
            $this->validateClaims($claims, $clientId, $allowedAudiences);

            $jti = (string) $claims->jti;
            $expiresAt = (new DateTimeImmutable)->setTimestamp((int) $claims->exp);
            if (! $this->replays->remember($clientId, $jti, $expiresAt)) {
                throw OAuthServerException::invalidClient($request);
            }

            return $clientId;
        } catch (OAuthServerException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw OAuthServerException::invalidClient($request);
        }
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

    private function validateHeaders(stdClass $headers, string $expectedKeyId): void
    {
        if (($headers->alg ?? null) !== 'RS256'
            || ! is_string($headers->kid ?? null)
            || ! hash_equals($expectedKeyId, (string) $headers->kid)) {
            throw new \UnexpectedValueException('Invalid client assertion header.');
        }
    }

    /** @param list<string> $allowedAudiences */
    private function validateClaims(stdClass $claims, string $clientId, array $allowedAudiences): void
    {
        $issuer = $claims->iss ?? null;
        $subject = $claims->sub ?? null;
        $jti = $claims->jti ?? null;
        $issuedAt = $claims->iat ?? null;
        $expiresAt = $claims->exp ?? null;

        if ($issuer !== $clientId || $subject !== $clientId
            || ! is_string($jti) || $jti === '' || strlen($jti) > 256
            || ! is_numeric($issuedAt) || ! is_numeric($expiresAt)) {
            throw new \UnexpectedValueException('Invalid client assertion claims.');
        }

        $issuedAt = (int) $issuedAt;
        $expiresAt = (int) $expiresAt;
        $now = time();
        $maxLifetime = max(60, (int) config('oauth.ttl.client_assertion_seconds'));

        if ($expiresAt <= $issuedAt
            || ($expiresAt - $issuedAt) > $maxLifetime
            || $issuedAt < ($now - $maxLifetime)
            || $expiresAt > ($now + $maxLifetime)) {
            throw new \UnexpectedValueException('Invalid client assertion lifetime.');
        }

        $audiences = $claims->aud ?? null;
        if (is_string($audiences)) {
            $audiences = [$audiences];
        }
        if (! is_array($audiences) || array_intersect($allowedAudiences, $audiences) === []) {
            throw new \UnexpectedValueException('Invalid client assertion audience.');
        }
    }

    /** @param array<string, mixed> $parameters */
    private function boundedString(array $parameters, string $key, int $maxLength): string
    {
        $value = $parameters[$key] ?? null;

        return is_string($value) && strlen($value) <= $maxLength ? $value : '';
    }
}
