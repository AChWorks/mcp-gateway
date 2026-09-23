<?php

namespace App\Application\Sites;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteCredential;
use App\Domain\Sites\SiteOAuthFlow;
use App\Domain\Sites\SiteRevocationIntent;
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
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

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
            if ($lockedSite->revocationIntent()->exists()) {
                throw new SiteConnectionException('revocation_pending', 'This site cannot authenticate while credential revocation is incomplete.');
            }
            if ($lockedSite->targetReservation()->exists()) {
                throw new SiteConnectionException('target_reassignment_pending', 'This site cannot authenticate while its target reassignment is incomplete.');
            }

            $credential = $lockedSite->credential()->first();
            if (! $credential instanceof SiteCredential) {
                if ($lockedSite->connection_state !== SiteConnectionState::Disconnected) {
                    $this->requireReconnect($lockedSite, 'missing_credential');
                }
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
        $this->revokeCredential($site, false);
    }

    public function revokeForRemoval(Site $site): void
    {
        $this->revokeCredential($site, true);
    }

    private function beginLocked(Site $site): string
    {
        if ($site->revocationIntent()->exists()) {
            throw new SiteConnectionException('revocation_pending', 'Complete the pending credential revocation before starting a new authorization.');
        }
        if ($site->targetReservation()->exists()) {
            throw new SiteConnectionException('target_reassignment_pending', 'Complete the pending target reassignment before starting a new authorization.');
        }

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
        if ($site->revocationIntent()->exists()) {
            throw new SiteConnectionException('revocation_pending', 'This callback cannot complete while credential revocation is pending.');
        }
        if ($site->targetReservation()->exists()) {
            throw new SiteConnectionException('target_reassignment_pending', 'This callback cannot complete while target reassignment is pending.');
        }

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
            $failedAt = now();
            $failureCode = 'oauth_'.$this->safeErrorCode($error);
            $site->forceFill([
                'connection_state' => SiteConnectionState::Disconnected,
                'last_error_code' => $failureCode,
                'connected_at' => null,
                'last_failure_at' => $failedAt,
                'last_failure_code' => $failureCode,
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

        $connectedAt = now();
        $site->forceFill([
            'connection_state' => SiteConnectionState::Connected,
            'last_error_code' => null,
            'connected_at' => $connectedAt,
            'last_success_at' => $connectedAt,
        ])->save();

        return $site->refresh();
    }

    private function revokeCredential(Site $site, bool $forRemoval): void
    {
        $plan = $this->prepareRevocation($site, $forRemoval);

        foreach ($plan['tokens'] as $token) {
            try {
                $response = $this->http->postForm($plan['revocation_url'], [
                    'token' => $token,
                    'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                    'client_assertion' => $this->identity->assertion($plan['revocation_url']),
                ]);
            } catch (OutboundRequestException $exception) {
                $this->markRevocationFailure($plan['site_record_id'], $exception->reason);
                throw new SiteConnectionException($exception->reason, 'The remote credential could not be revoked safely.');
            }

            // The pinned Bridge can emit invalid_client before revocation is attempted
            // when additional-client metadata/JWKS resolution is temporarily unavailable.
            if ($response->status !== 200) {
                $this->markRevocationFailure($plan['site_record_id'], 'revocation_failed');
                throw new SiteConnectionException('revocation_failed', 'WP AI Bridge did not confirm credential revocation.');
            }
        }

        if ($plan['tokens'] !== []) {
            $this->assertDatabaseSessionContinuity($plan['database_session_id']);
        }
        $this->finalizeRevocation($plan['site_record_id'], $forRemoval);
    }

    /** @return array{site_record_id:string,revocation_url:string,tokens:list<string>,database_session_id:?int} */
    private function prepareRevocation(Site $site, bool $forRemoval): array
    {
        return $this->lifecycle->run($site, function (Site $lockedSite) use ($forRemoval): array {
            $targetReassignment = $lockedSite->targetReservation()->exists();
            $intent = $lockedSite->revocationIntent()->first();

            if ($forRemoval) {
                if (! $intent instanceof SiteRevocationIntent) {
                    $intent = SiteRevocationIntent::query()->create([
                        'site_record_id' => (string) $lockedSite->getKey(),
                        'kind' => SiteRevocationIntent::KIND_REMOVE,
                    ]);
                } elseif ($intent->kind !== SiteRevocationIntent::KIND_REMOVE) {
                    $intent->forceFill(['kind' => SiteRevocationIntent::KIND_REMOVE])->save();
                }
            } elseif ($targetReassignment) {
                if ($intent instanceof SiteRevocationIntent) {
                    throw new SiteConnectionException('revocation_pending', 'A separate credential revocation operation already owns this site.');
                }
            } else {
                if ($intent instanceof SiteRevocationIntent && $intent->kind === SiteRevocationIntent::KIND_REMOVE) {
                    throw new SiteConnectionException('removal_pending', 'This site is already pending removal.');
                }
                if (! $intent instanceof SiteRevocationIntent) {
                    $intent = SiteRevocationIntent::query()->create([
                        'site_record_id' => (string) $lockedSite->getKey(),
                        'kind' => SiteRevocationIntent::KIND_DISCONNECT,
                    ]);
                }
            }

            SiteOAuthFlow::query()->where('site_record_id', $lockedSite->getKey())->delete();
            $lockedSite->forceFill([
                'connection_state' => $targetReassignment && ! $forRemoval
                    ? SiteConnectionState::Reassigning
                    : SiteConnectionState::Error,
                'last_error_code' => $targetReassignment && ! $forRemoval
                    ? null
                    : ($forRemoval ? 'removal_pending' : 'disconnect_pending'),
                'connected_at' => null,
            ])->save();

            $tokens = [];
            $credential = $lockedSite->credential()->first();
            if ($credential instanceof SiteCredential) {
                $secret = $this->credentials->open($credential);
                $tokens = array_values(array_filter(
                    [$secret->refreshToken, $secret->accessToken],
                    static fn (?string $token): bool => is_string($token) && $token !== '',
                ));
            }

            return [
                'site_record_id' => (string) $lockedSite->getKey(),
                'revocation_url' => $lockedSite->oauth_revocation_url,
                'tokens' => $tokens,
                'database_session_id' => $tokens === [] ? null : $this->currentDatabaseSessionId(),
            ];
        });
    }

    private function finalizeRevocation(string $siteRecordId, bool $forRemoval): void
    {
        $this->lifecycle->runForId($siteRecordId, function (Site $lockedSite) use ($forRemoval): void {
            $intent = $lockedSite->revocationIntent()->first();
            $targetReassignment = $lockedSite->targetReservation()->exists();
            $credential = $lockedSite->credential()->first();

            if ($forRemoval) {
                if (! $intent instanceof SiteRevocationIntent || $intent->kind !== SiteRevocationIntent::KIND_REMOVE) {
                    throw new SiteConnectionException('revocation_intent_lost', 'The durable site-removal revocation intent is no longer authoritative.');
                }
            } elseif ($intent instanceof SiteRevocationIntent && $intent->kind === SiteRevocationIntent::KIND_REMOVE) {
                // Removal took ownership while an ordinary/target disconnect was remotely executing.
            } elseif ($targetReassignment) {
                if ($intent instanceof SiteRevocationIntent) {
                    throw new SiteConnectionException('revocation_intent_conflict', 'Target reassignment cannot finalize while another revocation intent exists.');
                }
            } elseif (! $intent instanceof SiteRevocationIntent) {
                $alreadyDisconnected = ! SiteCredential::query()
                    ->where('site_record_id', $lockedSite->getKey())
                    ->exists()
                    && (string) $lockedSite->getRawOriginal('connection_state') === SiteConnectionState::Disconnected->value;
                if ($alreadyDisconnected) {
                    return;
                }
                throw new SiteConnectionException('revocation_intent_lost', 'The durable disconnect intent is no longer authoritative.');
            } elseif ($intent->kind !== SiteRevocationIntent::KIND_DISCONNECT) {
                throw new SiteConnectionException('revocation_intent_conflict', 'The durable disconnect intent changed unexpectedly.');
            }

            if ($credential instanceof SiteCredential) {
                $credential->delete();
            }
            SiteOAuthFlow::query()->where('site_record_id', $lockedSite->getKey())->delete();

            if ($intent instanceof SiteRevocationIntent && $intent->kind === SiteRevocationIntent::KIND_REMOVE) {
                $lockedSite->forceFill([
                    'connection_state' => SiteConnectionState::Error,
                    'last_error_code' => 'removal_pending',
                    'connected_at' => null,
                ])->save();

                return;
            }

            if ($targetReassignment) {
                $lockedSite->forceFill([
                    'connection_state' => SiteConnectionState::Reassigning,
                    'last_error_code' => null,
                    'connected_at' => null,
                ])->save();

                return;
            }

            $intent?->delete();
            $lockedSite->forceFill([
                'connection_state' => SiteConnectionState::Disconnected,
                'last_error_code' => null,
                'connected_at' => null,
            ])->save();
        });
    }

    private function markRevocationFailure(string $siteRecordId, string $reason): void
    {
        $this->lifecycle->runForId($siteRecordId, function (Site $lockedSite) use ($reason): void {
            $hasIntent = $lockedSite->revocationIntent()->exists();
            $failedAt = now();
            $failureCode = Str::limit($this->safeErrorCode($reason), 64, '');
            $lockedSite->forceFill([
                'connection_state' => ! $hasIntent && $lockedSite->targetReservation()->exists()
                    ? SiteConnectionState::Reassigning
                    : SiteConnectionState::Error,
                'last_error_code' => $failureCode,
                'connected_at' => null,
                'last_failure_at' => $failedAt,
                'last_failure_code' => $failureCode,
            ])->save();
        });
    }

    private function currentDatabaseSessionId(): ?int
    {
        if (! in_array(DB::connection()->getDriverName(), ['mariadb', 'mysql'], true)) {
            return null;
        }

        $row = DB::selectOne('SELECT CONNECTION_ID() AS connection_id');
        $connectionId = is_object($row) ? (int) ($row->connection_id ?? 0) : 0;
        if ($connectionId <= 0) {
            throw new RuntimeException('Could not resolve the active database session for durable revocation fencing.');
        }

        return $connectionId;
    }

    private function assertDatabaseSessionContinuity(?int $expectedSessionId): void
    {
        if ($expectedSessionId === null) {
            return;
        }

        $currentSessionId = $this->currentDatabaseSessionId();
        if ($currentSessionId !== $expectedSessionId) {
            throw new RuntimeException('The database session changed after remote revocation; durable local finalization requires an explicit retry.');
        }
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
            'last_success_at' => now(),
        ])->save();

        return $token['access_token'];
    }

    private function discoverAndPersist(Site $site): BridgeDiscovery
    {
        try {
            $discovery = $this->discovery->discover($site->base_url);
        } catch (BridgeDiscoveryException $exception) {
            $checkedAt = now();
            $site->forceFill([
                'connection_state' => SiteConnectionState::Error,
                'last_error_code' => $exception->reason,
                'last_tested_at' => $checkedAt,
                'last_failure_at' => $checkedAt,
                'last_failure_code' => $exception->reason,
            ])->save();
            throw new SiteConnectionException($exception->reason, $exception->getMessage());
        }

        $checkedAt = now();
        $site->forceFill([
            'base_url' => $discovery->baseUrl,
            'base_url_hash' => hash('sha256', $discovery->baseUrl),
            'mcp_resource_url' => $discovery->resourceUrl,
            'oauth_issuer_url' => $discovery->issuerUrl,
            'oauth_authorization_url' => $discovery->authorizationUrl,
            'oauth_token_url' => $discovery->tokenUrl,
            'oauth_revocation_url' => $discovery->revocationUrl,
            'last_error_code' => null,
            'last_tested_at' => $checkedAt,
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
        $failedAt = now();
        $failureCode = Str::limit($this->safeErrorCode($code), 64, '');
        $site->forceFill([
            'connection_state' => SiteConnectionState::Error,
            'last_error_code' => $failureCode,
            'last_failure_at' => $failedAt,
            'last_failure_code' => $failureCode,
        ])->save();
    }

    private function requireReconnect(Site $site, string $code): void
    {
        $failedAt = now();
        $failureCode = Str::limit($this->safeErrorCode($code), 64, '');
        $site->forceFill([
            'connection_state' => SiteConnectionState::ReconnectRequired,
            'last_error_code' => $failureCode,
            'connected_at' => null,
            'last_failure_at' => $failedAt,
            'last_failure_code' => $failureCode,
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
        // invalid_client is ambiguous in the pinned Bridge contract because transient
        // additional-client metadata/JWKS failures are normalized to that OAuth code.
        return $oauthError === 'invalid_grant';
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
