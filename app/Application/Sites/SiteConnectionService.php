<?php

namespace App\Application\Sites;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteCredential;
use App\Domain\Sites\SiteOAuthFlow;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscovery;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeDiscovery;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use App\Infrastructure\OAuth\SiteCredentialSecret;
use App\Infrastructure\OAuth\SiteCredentialVault;
use App\Infrastructure\OAuth\SiteOAuthFlowContext;
use App\Infrastructure\OAuth\SiteOAuthFlowVault;
use DateTimeImmutable;
use Illuminate\Support\Str;

final class SiteConnectionService
{
    public function __construct(
        private readonly WpAiBridgeDiscovery $discovery,
        private readonly SafeHttpClient $http,
        private readonly GatewayBridgeClientIdentity $identity,
        private readonly SiteCredentialVault $credentials,
        private readonly SiteOAuthFlowVault $flows,
        private readonly SiteLifecycleLock $lifecycle,
    ) {}

    public function begin(Site $site): string
    {
        return $this->lifecycle->run($site, fn (Site $lockedSite): string => $this->beginLocked($lockedSite));
    }

    public function completeCallback(string $state, ?string $code, ?string $issuer, ?string $error): Site
    {
        if ($state === '' || strlen($state) > 512 || preg_match('/^[A-Za-z0-9_-]+$/', $state) !== 1) {
            throw new SiteConnectionException('invalid_state', 'The site OAuth callback state is invalid.');
        }

        $stateHash = hash('sha256', $state);
        $flow = SiteOAuthFlow::query()->where('state_hash', $stateHash)->first();
        if (! $flow instanceof SiteOAuthFlow || $flow->consumed_at !== null || $flow->expires_at->isPast()) {
            throw new SiteConnectionException('invalid_state', 'The site OAuth callback state is expired or already used.');
        }

        return $this->lifecycle->runForId(
            $flow->site_record_id,
            fn (Site $lockedSite): Site => $this->completeCallbackLocked(
                $lockedSite,
                $stateHash,
                $code,
                $issuer,
                $error,
            ),
        );
    }

    public function accessToken(Site $site): string
    {
        return $this->lifecycle->run($site, function (Site $lockedSite): string {
            $credential = $lockedSite->credential()->first();
            if (! $credential instanceof SiteCredential) {
                $this->requireReconnect($lockedSite, 'missing_credential');
                throw new SiteConnectionException('missing_credential', 'This site does not have an active OAuth credential.');
            }

            $secret = $this->credentials->open($credential);
            if ($secret->accessExpiresAt === null || $secret->accessExpiresAt->getTimestamp() > time() + 30) {
                return $secret->accessToken;
            }

            return $this->refresh($lockedSite, $credential, $secret);
        });
    }

    public function disconnect(Site $site): void
    {
        $this->lifecycle->run($site, function (Site $lockedSite): void {
            $this->disconnectLocked($lockedSite);
        });
    }

    private function beginLocked(Site $site): string
    {
        if ($site->credential()->exists()) {
            throw new SiteConnectionException('already_connected', 'Disconnect the current site credential before starting a new authorization.');
        }

        $discovery = $this->discoverAndPersist($site);
        $state = $this->randomBase64Url(32);
        $stateHash = hash('sha256', $state);
        $verifier = $this->randomBase64Url(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $clientId = $this->identity->clientId();
        $redirectUri = $this->identity->redirectUri();

        SiteOAuthFlow::query()->where('site_record_id', $site->getKey())->delete();

        $flowExpiresAt = now()->addSeconds(max(60, (int) config('bridge.oauth.flow_ttl_seconds', 600)));
        $flow = new SiteOAuthFlow([
            'site_record_id' => (string) $site->getKey(),
            'state_hash' => $stateHash,
            'expires_at' => $flowExpiresAt,
        ]);
        $flow->encrypted_context = $this->flows->seal(
            $site,
            $stateHash,
            $clientId,
            $redirectUri,
            $discovery->resourceUrl,
            $discovery->issuerUrl,
            $discovery->tokenUrl,
            $discovery->revocationUrl,
            $verifier,
            $flowExpiresAt->getTimestamp(),
        );
        $flow->save();

        $site->forceFill([
            'connection_state' => SiteConnectionState::Pending,
            'last_error_code' => null,
        ])->save();

        $query = http_build_query([
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => $discovery->resourceUrl,
            'scope' => $this->requestedScope(),
            'state' => $state,
        ], '', '&', PHP_QUERY_RFC3986);

        return $discovery->authorizationUrl.'?'.$query;
    }

    private function completeCallbackLocked(
        Site $site,
        string $stateHash,
        ?string $code,
        ?string $issuer,
        ?string $error,
    ): Site {
        $flow = SiteOAuthFlow::query()
            ->where('site_record_id', $site->getKey())
            ->where('state_hash', $stateHash)
            ->lockForUpdate()
            ->first();
        if (! $flow instanceof SiteOAuthFlow || $flow->consumed_at !== null || $flow->expires_at->isPast()) {
            throw new SiteConnectionException('invalid_state', 'The site OAuth callback state is expired or already used.');
        }

        try {
            $context = $this->flows->open($flow);
        } catch (\Throwable $exception) {
            $flow->delete();
            $this->requireReconnect($site, 'invalid_state');
            throw new SiteConnectionException('invalid_state', 'The site OAuth callback state binding is invalid.');
        }

        if ($issuer === null || ! hash_equals($context->issuerUrl, rtrim($issuer, '/'))) {
            throw new SiteConnectionException('issuer_mismatch', 'The site OAuth callback issuer does not match the paired site.');
        }

        $flow->forceFill(['consumed_at' => now()])->save();

        if ($error !== null && $error !== '') {
            $flow->delete();
            $site->forceFill([
                'connection_state' => SiteConnectionState::Disconnected,
                'last_error_code' => 'oauth_'.$this->safeErrorCode($error),
                'connected_at' => null,
            ])->save();

            throw new SiteConnectionException('authorization_denied', 'The WordPress authorization was not completed.');
        }
        if ($code === null || $code === '' || strlen($code) > 1024) {
            $flow->delete();
            $this->requireReconnect($site, 'invalid_callback');
            throw new SiteConnectionException('invalid_callback', 'The site OAuth callback did not include a valid authorization code.');
        }

        try {
            $response = $this->http->postForm($context->tokenUrl, [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $context->clientId,
                'redirect_uri' => $context->redirectUri,
                'code_verifier' => $context->codeVerifier,
                'resource' => $context->resourceUrl,
                'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                'client_assertion' => $this->identity->assertion($context->tokenUrl),
            ]);
        } catch (OutboundRequestException $exception) {
            $this->requireReconnect($site, $exception->reason);
            throw new SiteConnectionException($exception->reason, 'The WP AI Bridge token endpoint could not be reached safely.');
        }

        if ($response->status !== 200) {
            $this->requireReconnect($site, $this->oauthFailureCode($response->body));
            throw new SiteConnectionException('token_exchange_failed', 'WP AI Bridge rejected the authorization-code exchange.');
        }

        try {
            $token = $this->parseTokenResponse($response->json());
        } catch (SiteConnectionException|OutboundRequestException $exception) {
            $reason = $exception->reason;
            $this->requireReconnect($site, $reason);
            throw new SiteConnectionException($reason, 'WP AI Bridge returned an unusable token response.');
        }
        $this->persistCredential($site, $context, $token);
        $flow->delete();

        $site->forceFill([
            'connection_state' => SiteConnectionState::Connected,
            'last_error_code' => null,
            'connected_at' => now(),
        ])->save();

        return $site->refresh();
    }

    private function disconnectLocked(Site $site): void
    {
        $credential = $site->credential()->first();
        if ($credential instanceof SiteCredential) {
            $secret = $this->credentials->open($credential);
            $tokens = array_values(array_filter([$secret->refreshToken, $secret->accessToken], static fn (?string $token): bool => is_string($token) && $token !== ''));

            foreach ($tokens as $token) {
                try {
                    $response = $this->http->postForm($site->oauth_revocation_url, [
                        'token' => $token,
                        'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                        'client_assertion' => $this->identity->assertion($site->oauth_revocation_url),
                    ]);
                } catch (OutboundRequestException $exception) {
                    $site->forceFill([
                        'connection_state' => SiteConnectionState::Error,
                        'last_error_code' => $exception->reason,
                    ])->save();
                    throw new SiteConnectionException($exception->reason, 'The remote credential could not be revoked safely.');
                }

                if ($response->status !== 200 && ! $this->isAlreadyInvalidClient($response->status, $response->body)) {
                    $site->forceFill([
                        'connection_state' => SiteConnectionState::Error,
                        'last_error_code' => 'revocation_failed',
                    ])->save();
                    throw new SiteConnectionException('revocation_failed', 'WP AI Bridge did not confirm credential revocation.');
                }
            }

            $credential->delete();
        }

        SiteOAuthFlow::query()->where('site_record_id', $site->getKey())->delete();
        $site->forceFill([
            'connection_state' => SiteConnectionState::Disconnected,
            'last_error_code' => null,
            'connected_at' => null,
        ])->save();
    }

    private function refresh(Site $site, SiteCredential $credential, SiteCredentialSecret $secret): string
    {
        if ($secret->refreshToken === null || $secret->refreshToken === '') {
            $credential->delete();
            $this->requireReconnect($site, 'refresh_unavailable');
            throw new SiteConnectionException('refresh_unavailable', 'This site connection cannot be refreshed and must be reconnected.');
        }

        try {
            $response = $this->http->postForm($site->oauth_token_url, [
                'grant_type' => 'refresh_token',
                'refresh_token' => $secret->refreshToken,
                'client_id' => $credential->client_id,
                'resource' => $credential->resource_url,
                'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                'client_assertion' => $this->identity->assertion($site->oauth_token_url),
            ]);
        } catch (OutboundRequestException $exception) {
            $this->markRecoverableError($site, $exception->reason);
            throw new SiteConnectionException($exception->reason, 'The WP AI Bridge refresh endpoint could not be reached safely.');
        }

        if ($response->status !== 200) {
            if ($response->status >= 500) {
                $this->markRecoverableError($site, 'remote_failure');
                throw new SiteConnectionException('remote_failure', 'WP AI Bridge refresh is temporarily unavailable.');
            }

            $oauthError = $this->oauthFailureCode($response->body);
            if (! $this->isTerminalRefreshFailure($oauthError)) {
                $this->markRecoverableError($site, $oauthError);
                throw new SiteConnectionException($oauthError, 'WP AI Bridge refresh failed without proving that the stored authorization is terminal.');
            }

            $credential->delete();
            $this->requireReconnect($site, $oauthError);
            throw new SiteConnectionException('refresh_failed', 'The site OAuth refresh was rejected and requires reconnection.');
        }

        try {
            $token = $this->parseTokenResponse($response->json());
        } catch (SiteConnectionException|OutboundRequestException $exception) {
            $reason = $exception->reason;
            $this->markRecoverableError($site, $reason);
            throw new SiteConnectionException($reason, 'WP AI Bridge returned an unusable refresh response.');
        }
        $context = new SiteOAuthFlowContext(
            (string) $site->getKey(),
            $credential->client_id,
            $this->identity->redirectUri(),
            $credential->resource_url,
            $site->oauth_issuer_url,
            $site->oauth_token_url,
            $site->oauth_revocation_url,
            '',
        );
        $this->persistCredential($site, $context, $token);
        $site->forceFill([
            'connection_state' => SiteConnectionState::Connected,
            'last_error_code' => null,
        ])->save();

        return $token['access_token'];
    }

    private function discoverAndPersist(Site $site): BridgeDiscovery
    {
        try {
            $discovery = $this->discovery->discover($site->base_url);
        } catch (BridgeDiscoveryException $exception) {
            $site->forceFill([
                'connection_state' => SiteConnectionState::Error,
                'last_error_code' => $exception->reason,
                'last_tested_at' => now(),
            ])->save();
            throw new SiteConnectionException($exception->reason, $exception->getMessage());
        }

        $site->forceFill([
            'base_url' => $discovery->baseUrl,
            'base_url_hash' => hash('sha256', $discovery->baseUrl),
            'mcp_resource_url' => $discovery->resourceUrl,
            'oauth_issuer_url' => $discovery->issuerUrl,
            'oauth_authorization_url' => $discovery->authorizationUrl,
            'oauth_token_url' => $discovery->tokenUrl,
            'oauth_revocation_url' => $discovery->revocationUrl,
            'last_error_code' => null,
            'last_tested_at' => now(),
        ])->save();

        return $discovery;
    }

    /**
     * @param  array<string, mixed>  $document
     * @return array{access_token:string,refresh_token:?string,expires_at:?DateTimeImmutable,scopes:list<string>}
     */
    private function parseTokenResponse(array $document): array
    {
        $accessToken = $document['access_token'] ?? null;
        $refreshToken = $document['refresh_token'] ?? null;
        $tokenType = $document['token_type'] ?? null;
        $expiresIn = $document['expires_in'] ?? null;
        $scope = $document['scope'] ?? null;

        if (! is_string($accessToken) || $accessToken === '' || strlen($accessToken) > 8192 || ! is_string($tokenType) || strcasecmp($tokenType, 'Bearer') !== 0) {
            throw new SiteConnectionException('invalid_token_response', 'WP AI Bridge returned an invalid access-token response.');
        }
        if ($refreshToken !== null && (! is_string($refreshToken) || $refreshToken === '' || strlen($refreshToken) > 8192)) {
            throw new SiteConnectionException('invalid_token_response', 'WP AI Bridge returned an invalid refresh token.');
        }
        if (! is_numeric($expiresIn) || (int) $expiresIn < 1 || (int) $expiresIn > 86400) {
            throw new SiteConnectionException('invalid_token_response', 'WP AI Bridge returned an invalid access-token lifetime.');
        }

        $scopes = is_string($scope) ? preg_split('/ +/', trim($scope)) : [];
        $scopes = is_array($scopes) ? array_values(array_filter($scopes, static fn (string $value): bool => $value !== '')) : [];
        if (! in_array((string) config('bridge.oauth.scope', 'mcp:use'), $scopes, true)) {
            throw new SiteConnectionException('invalid_token_response', 'WP AI Bridge token response is missing the required MCP scope.');
        }
        if (! in_array((string) config('bridge.oauth.offline_scope', 'offline_access'), $scopes, true) || $refreshToken === null) {
            throw new SiteConnectionException('invalid_token_response', 'WP AI Bridge token response is missing the required offline refresh authorization.');
        }

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'expires_at' => new DateTimeImmutable('@'.(time() + (int) $expiresIn)),
            'scopes' => $scopes,
        ];
    }

    /** @param array{access_token:string,refresh_token:?string,expires_at:?DateTimeImmutable,scopes:list<string>} $token */
    private function persistCredential(Site $site, SiteOAuthFlowContext $context, array $token): void
    {
        $payload = $this->credentials->seal(
            $site,
            $context->clientId,
            $context->resourceUrl,
            $token['access_token'],
            $token['refresh_token'],
            $token['expires_at'],
            $token['scopes'],
        );

        SiteCredential::query()->updateOrCreate(
            ['site_record_id' => $site->getKey()],
            [
                'client_id' => $context->clientId,
                'resource_url' => $context->resourceUrl,
                'binding_hash' => SiteCredentialVault::bindingHash($site, $context->clientId, $context->resourceUrl),
                'encrypted_payload' => $payload,
                'access_expires_at' => $token['expires_at'],
            ],
        );
    }

    private function markRecoverableError(Site $site, string $code): void
    {
        $site->forceFill([
            'connection_state' => SiteConnectionState::Error,
            'last_error_code' => Str::limit($this->safeErrorCode($code), 64, ''),
        ])->save();
    }

    private function requireReconnect(Site $site, string $code): void
    {
        $site->forceFill([
            'connection_state' => SiteConnectionState::ReconnectRequired,
            'last_error_code' => Str::limit($this->safeErrorCode($code), 64, ''),
            'connected_at' => null,
        ])->save();
    }

    private function requestedScope(): string
    {
        return trim((string) config('bridge.oauth.scope', 'mcp:use').' '.(string) config('bridge.oauth.offline_scope', 'offline_access'));
    }

    private function oauthFailureCode(string $body): string
    {
        $document = json_decode($body, true);
        $error = is_array($document) && is_string($document['error'] ?? null) ? $document['error'] : 'oauth_rejected';

        return $this->safeErrorCode($error);
    }

    private function isTerminalRefreshFailure(string $oauthError): bool
    {
        return in_array($oauthError, ['invalid_grant', 'invalid_client'], true);
    }

    private function isAlreadyInvalidClient(int $status, string $body): bool
    {
        if ($status < 400 || $status >= 500) {
            return false;
        }

        return $this->oauthFailureCode($body) === 'invalid_client';
    }

    private function safeErrorCode(string $value): string
    {
        $safe = strtolower(preg_replace('/[^a-zA-Z0-9_.-]+/', '_', $value) ?? 'error');

        return trim($safe, '_') !== '' ? trim($safe, '_') : 'error';
    }

    private function randomBase64Url(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
