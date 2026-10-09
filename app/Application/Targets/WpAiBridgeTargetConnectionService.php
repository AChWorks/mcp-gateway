<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeDiscovery;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use DateTimeImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

final readonly class WpAiBridgeTargetConnectionService
{
    private const PURPOSE = 'wordpress_oauth';

    public function __construct(
        private WpAiBridgeDiscovery $discovery,
        private SafeHttpClient $http,
        private GatewayBridgeClientIdentity $identity,
        private WpAiBridgeTargetVault $vault,
    ) {}

    public function begin(Target $target): string
    {
        $this->requireWordpress($target);
        $configuration = $this->configuration((string) $target->getKey());

        // Discovery is untrusted remote I/O: never hold a database row lock.
        try {
            $discovery = $this->discovery->discover($configuration->base_url);
        } catch (BridgeDiscoveryException $exception) {
            $this->recordDiscoveryFailure((string) $target->getKey(), $exception->reason);
            throw new WpAiBridgeTargetConnectionException($exception->reason, 'WordPress metadata could not be verified safely.');
        }

        $clientId = $this->identity->clientId();
        $redirect = $this->identity->redirectUri();
        $state = $this->randomBase64Url(32);
        $stateHash = hash('sha256', $state);
        $verifier = $this->randomBase64Url(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $expiresAt = now()->addSeconds(max(60, (int) config('bridge.oauth.flow_ttl_seconds', 600)));

        $this->withLockedTarget((string) $target->getKey(), function (Target $locked) use (
            $configuration, $discovery, $clientId, $redirect, $stateHash, $verifier, $expiresAt,
        ): void {
            $this->ensureReadyForConnect($locked);
            $current = $this->configuration((string) $locked->getKey());

            if ((string) $current->base_url !== (string) $configuration->base_url
                || ! hash_equals((string) $current->base_url, $discovery->baseUrl)) {
                throw new WpAiBridgeTargetConnectionException('target_changed', 'The WordPress Target origin changed during discovery.');
            }

            DB::table('wp_ai_bridge_target_configs')->where('target_record_id', $locked->getKey())->update([
                'mcp_resource_url' => $discovery->resourceUrl,
                'oauth_issuer_url' => $discovery->issuerUrl,
                'oauth_authorization_url' => $discovery->authorizationUrl,
                'oauth_token_url' => $discovery->tokenUrl,
                'oauth_revocation_url' => $discovery->revocationUrl,
                'updated_at' => now(),
            ]);

            $existing = DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())->first();
            // A consumed callback may have an in-flight remote token exchange.
            // Do not silently replace that claim, even on another browser request.
            if ($existing !== null && $existing->consumed_at !== null) {
                throw new WpAiBridgeTargetConnectionException('callback_pending', 'An OAuth callback is still being reconciled.');
            }

            DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())->delete();
            DB::table('wp_ai_bridge_oauth_flows')->insert([
                'id' => (string) Str::ulid(),
                'target_record_id' => $locked->getKey(),
                'state_hash' => $stateHash,
                'encrypted_context' => $this->vault->sealFlow($locked, $stateHash, [
                    'client_id' => $clientId,
                    'redirect_uri' => $redirect,
                    'resource_url' => $discovery->resourceUrl,
                    'issuer_url' => $discovery->issuerUrl,
                    'token_url' => $discovery->tokenUrl,
                    'revocation_url' => $discovery->revocationUrl,
                    'code_verifier' => $verifier,
                ], $expiresAt->getTimestamp()),
                'expires_at' => $expiresAt,
                'consumed_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Pending,
                'last_error_code' => null,
                'last_tested_at' => now(),
            ])->save();
        });

        return $discovery->authorizationUrl.'?'.http_build_query([
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'response_type' => 'code',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => $discovery->resourceUrl,
            'scope' => $this->requestedScope(),
            'state' => $state,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function completeCallback(string $state, ?string $code, ?string $issuer, ?string $error): Target
    {
        if ($state === '' || strlen($state) > 512 || preg_match('/^[A-Za-z0-9_-]+$/D', $state) !== 1) {
            throw new WpAiBridgeTargetConnectionException('invalid_state', 'The OAuth callback state is invalid.');
        }

        $stateHash = hash('sha256', $state);
        $flow = DB::table('wp_ai_bridge_oauth_flows')->where('state_hash', $stateHash)->first();
        if ($flow === null || $flow->consumed_at !== null || now()->greaterThanOrEqualTo($flow->expires_at)) {
            throw new WpAiBridgeTargetConnectionException('invalid_state', 'The OAuth callback state has expired or was used.');
        }
        $recordId = (string) $flow->target_record_id;

        /** @var array{context:array{client_id:string,redirect_uri:string,resource_url:string,issuer_url:string,token_url:string,revocation_url:string,code_verifier:string},denied:bool} $claim */
        $claim = $this->withLockedTarget($recordId, function (Target $locked) use ($stateHash, $issuer, $error, $code): array {
            $pending = DB::table('wp_ai_bridge_oauth_flows')
                ->where('target_record_id', $locked->getKey())
                ->where('state_hash', $stateHash)
                ->lockForUpdate()->first();

            if ($pending === null || $pending->consumed_at !== null || now()->greaterThanOrEqualTo($pending->expires_at)
                || $locked->getAttribute('connection_state') !== TargetConnectionState::Pending
                || $this->hasRevocationIntent($locked)) {
                throw new WpAiBridgeTargetConnectionException('invalid_state', 'The OAuth flow is no longer active.');
            }

            try {
                $context = $this->vault->openFlow($locked, $pending);
            } catch (RuntimeException) {
                throw new WpAiBridgeTargetConnectionException('invalid_state', 'OAuth flow binding cannot be verified.');
            }
            $config = $this->configuration((string) $locked->getKey());
            if (! hash_equals((string) $config->oauth_issuer_url, $context['issuer_url'])
                || ! hash_equals((string) $config->oauth_token_url, $context['token_url'])
                || ! hash_equals((string) $config->mcp_resource_url, $context['resource_url'])
                || ! is_string($issuer)
                || ! hash_equals($context['issuer_url'], rtrim($issuer, '/'))) {
                throw new WpAiBridgeTargetConnectionException('issuer_mismatch', 'OAuth callback issuer or stored connection metadata does not match.');
            }

            DB::table('wp_ai_bridge_oauth_flows')
                ->where('id', $pending->id)->update(['consumed_at' => now(), 'updated_at' => now()]);

            if (($error !== null && $error !== '') || ! is_string($code) || $code === '' || strlen($code) > 1024) {
                DB::table('wp_ai_bridge_oauth_flows')->where('id', $pending->id)->delete();
                $reason = $error !== null && $error !== '' ? 'oauth_'.$this->safeError($error) : 'invalid_callback';
                $this->setFailure($locked, $reason, TargetConnectionState::Disconnected);

                return ['context' => $context, 'denied' => true];
            }

            return ['context' => $context, 'denied' => false];
        });

        if ($claim['denied']) {
            throw new WpAiBridgeTargetConnectionException('authorization_denied', 'The WordPress authorization was not completed.');
        }

        // State is durably claimed before any outbound token exchange. Never
        // automatically retry an ambiguous authorization-code exchange.
        try {
            $response = $this->http->postForm($claim['context']['token_url'], [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $claim['context']['client_id'],
                'redirect_uri' => $claim['context']['redirect_uri'],
                'code_verifier' => $claim['context']['code_verifier'],
                'resource' => $claim['context']['resource_url'],
                'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                'client_assertion' => $this->identity->assertion($claim['context']['token_url']),
            ]);
            if ($response->status !== 200) {
                throw new WpAiBridgeTargetConnectionException('token_exchange_failed', 'WP AI Bridge rejected authorization.');
            }
            $token = $this->parseToken($response->json());
        } catch (OutboundRequestException $exception) {
            $this->failClaim($recordId, $stateHash, $exception->reason);
            throw new WpAiBridgeTargetConnectionException($exception->reason, 'WP AI Bridge token exchange could not complete safely.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            $this->failClaim($recordId, $stateHash, $exception->reason);
            throw $exception;
        }

        return $this->withLockedTarget($recordId, function (Target $locked) use ($stateHash, $claim, $token): Target {
            $pending = DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())
                ->where('state_hash', $stateHash)->lockForUpdate()->first();
            $config = $this->configuration((string) $locked->getKey());
            if ($pending === null || $pending->consumed_at === null
                || $locked->getAttribute('connection_state') !== TargetConnectionState::Pending
                || $this->hasRevocationIntent($locked)
                || ! hash_equals((string) $config->oauth_token_url, $claim['context']['token_url'])
                || ! hash_equals((string) $config->mcp_resource_url, $claim['context']['resource_url'])) {
                throw new WpAiBridgeTargetConnectionException('callback_conflict', 'Target state changed during the remote token exchange.');
            }

            if ($this->credential($locked) instanceof TargetCredential) {
                throw new WpAiBridgeTargetConnectionException('already_connected', 'This Target already holds an OAuth credential.');
            }

            $encrypted = $this->vault->sealCredential(
                $locked,
                $claim['context']['client_id'],
                $claim['context']['resource_url'],
                $token['access_token'],
                $token['refresh_token'],
                $token['expires_at'],
                $token['scopes'],
            );

            $credential = TargetCredential::query()->create([
                'target_record_id' => $locked->getKey(),
                'connector_type' => 'wp_ai_bridge',
                'purpose' => self::PURPOSE,
                'encrypted_payload' => $encrypted,
            ]);
            DB::table('wp_ai_bridge_credential_metadata')->insert([
                'credential_id' => $credential->getKey(),
                'client_id' => $claim['context']['client_id'],
                'resource_url' => $claim['context']['resource_url'],
                'binding_hash' => hash('sha256', (string) $locked->getKey()."\0".$locked->target_id."\0".$claim['context']['client_id']."\0".$claim['context']['resource_url']),
                'access_expires_at' => $token['expires_at'],
                'refresh_expires_at' => $token['refresh_expires_at'],
                'refresh_due_at' => $token['refresh_due_at'],
            ]);

            DB::table('wp_ai_bridge_oauth_flows')->where('id', $pending->id)->delete();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Connected,
                'last_error_code' => null,
                'connected_at' => now(),
                'last_success_at' => now(),
            ])->save();

            return $locked->refresh();
        });
    }

    /**
     * Target-bound credential snapshot or a fenced refresh, never remote I/O
     * under the Target row lock. The remote WP issuer rotates refresh tokens.
     *
     * @return array{resource_url:string,access_token:string}
     */
    public function routingContext(Target $target, bool $renewIfDue = false): array
    {
        $recordId = (string) $target->getKey();
        /** @var array<string,mixed> $plan */
        $plan = $this->withLockedTarget($recordId, function (Target $locked) use ($renewIfDue): array {
            if ($this->hasRevocationIntent($locked)) {
                throw new WpAiBridgeTargetConnectionException('revocation_pending', 'Credential revocation is incomplete.');
            }
            $credential = $this->credential($locked);
            if (! $credential instanceof TargetCredential) {
                throw new WpAiBridgeTargetConnectionException('missing_credential', 'Target authorization has not been completed.');
            }
            try {
                $secret = $this->vault->openCredential($locked, $credential);
            } catch (RuntimeException) {
                throw new WpAiBridgeTargetConnectionException('credential_unavailable', 'The stored credential cannot be opened safely.');
            }

            $config = $this->configuration((string) $locked->getKey());
            if (! hash_equals((string) $config->mcp_resource_url, $secret['resource_url'])
                || ! hash_equals($this->identity->clientId(), $secret['client_id'])) {
                throw new WpAiBridgeTargetConnectionException('target_changed', 'WordPress credential binding has changed.');
            }
            $this->assertStoredSameOrigin($secret['resource_url'], (string) $config->base_url);
            $this->assertStoredSameOrigin((string) $config->oauth_token_url, (string) $config->base_url);

            $metadata = DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->getKey())->first();
            if ($metadata === null) {
                throw new WpAiBridgeTargetConnectionException('credential_unavailable', 'WordPress credential metadata is unavailable.');
            }
            $generation = (int) $metadata->generation;
            $intent = DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $locked->getKey())->first();

            if ($intent === null && $locked->getAttribute('connection_state') !== TargetConnectionState::Connected) {
                throw new WpAiBridgeTargetConnectionException('reconnect_required', 'The WordPress Target requires reconnection.');
            }
            $accessStillValid = $secret['access_expires_at'] !== null
                && $secret['access_expires_at']->getTimestamp() > time() + 30;
            $dueAt = $metadata->refresh_due_at === null ? null : strtotime((string) $metadata->refresh_due_at);
            if ($intent === null && $accessStillValid
                && (! $renewIfDue || ($dueAt !== null && $dueAt > time()))) {
                return ['ready' => true, 'resource_url' => $secret['resource_url'], 'access_token' => $secret['access_token']];
            }

            if ($intent === null && $metadata->refresh_expires_at !== null
                && strtotime((string) $metadata->refresh_expires_at) <= time()) {
                $this->setFailure($locked, 'refresh_expired', TargetConnectionState::Error);

                return ['expired' => true];
            }

            if ($intent === null) {
                $intentId = (string) Str::ulid();
                DB::table('wp_ai_bridge_refresh_intents')->insert([
                    'id' => $intentId,
                    'target_record_id' => $locked->getKey(),
                    'credential_id' => $credential->getKey(),
                    'generation' => $generation,
                    'attempts' => 1,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            } else {
                if ((string) $intent->credential_id !== (string) $credential->getKey()
                    || (int) $intent->generation !== $generation) {
                    throw new WpAiBridgeTargetConnectionException('refresh_conflict', 'Credential changed during refresh.');
                }
                // Remote issuer permits one exact old-token recovery for 60s.
                // Avoid overlapping an in-flight first request, and never
                // replay an already recovered or too-old exchange.
                $age = time() - (new DateTimeImmutable((string) $intent->created_at))->getTimestamp();
                $retryDelay = max(12, (int) config('bridge.http.request_timeout_seconds', 5) + 5);
                if ((int) $intent->attempts !== 1 || $age < $retryDelay || $age >= 45) {
                    throw new WpAiBridgeTargetConnectionException(
                        'refresh_pending',
                        'The prior WordPress refresh is unresolved; do not reuse its credentials.',
                    );
                }
                $intentId = (string) $intent->id;
                DB::table('wp_ai_bridge_refresh_intents')->where('id', $intentId)->update([
                    'attempts' => 2,
                    'updated_at' => now(),
                ]);
            }

            return [
                'ready' => false,
                'intent_id' => $intentId,
                'credential_id' => (string) $credential->getKey(),
                'generation' => $generation,
                'resource_url' => $secret['resource_url'],
                'refresh_token' => $secret['refresh_token'],
                'client_id' => $secret['client_id'],
                'scopes' => $secret['scopes'],
                'token_url' => (string) $config->oauth_token_url,
                'database_session_id' => $this->databaseSessionId(),
            ];
        });

        if (($plan['expired'] ?? false) === true) {
            throw new WpAiBridgeTargetConnectionException('refresh_expired',
                'WordPress offline authorization has expired and requires fresh consent.');
        }
        if (($plan['ready'] ?? false) === true) {
            return ['resource_url' => $plan['resource_url'], 'access_token' => $plan['access_token']];
        }

        return $this->exchangeRefresh($recordId, $plan);
    }

    public function accessToken(Target $target): string
    {
        return $this->routingContext($target)['access_token'];
    }

    /**
     * @param  array{intent_id:string,credential_id:string,generation:int,resource_url:string,refresh_token:string,client_id:string,scopes:list<string>,token_url:string,database_session_id:?int}  $plan
     * @return array{resource_url:string,access_token:string}
     */
    private function exchangeRefresh(string $recordId, array $plan): array
    {
        try {
            // Exact old token + client + resource is the WP Bridge's bounded
            // single-use recovery identity after a lost rotating response.
            $response = $this->http->postForm($plan['token_url'], [
                'grant_type' => 'refresh_token',
                'refresh_token' => $plan['refresh_token'],
                'client_id' => $plan['client_id'],
                'resource' => $plan['resource_url'],
                'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                'client_assertion' => $this->identity->assertion($plan['token_url']),
            ]);
        } catch (OutboundRequestException $exception) {
            $this->recordRefreshFailure($recordId, $plan, 'refresh_ambiguous');
            throw new WpAiBridgeTargetConnectionException('refresh_ambiguous',
                'The WordPress refresh outcome is unknown; do not retry an uncontrolled token rotation.');
        }

        if ($response->status !== 200) {
            // Only a transient/ambiguous response may use WP's one-shot
            // recovery. A definitive 4xx cannot be blindly replayed.
            $terminal = $response->status < 500
                && ! in_array($response->status, [408, 429], true);
            $reason = $terminal ? 'refresh_rejected' : 'refresh_ambiguous';
            $this->recordRefreshFailure($recordId, $plan, $reason, $terminal);
            throw new WpAiBridgeTargetConnectionException($reason,
                'WordPress did not confirm a usable refreshed credential.');
        }

        try {
            $token = $this->parseToken($response->json());
            $oldScopes = $plan['scopes'];
            $newScopes = $token['scopes'];
            sort($oldScopes);
            sort($newScopes);
            if ($oldScopes !== $newScopes
                || hash_equals($plan['refresh_token'], $token['refresh_token'])) {
                throw new WpAiBridgeTargetConnectionException('invalid_token_response',
                    'WordPress returned an incorrectly scoped or unrotated credential.');
            }
        } catch (OutboundRequestException|WpAiBridgeTargetConnectionException $exception) {
            $this->recordRefreshFailure($recordId, $plan, 'refresh_ambiguous');
            throw new WpAiBridgeTargetConnectionException('refresh_ambiguous',
                'WordPress returned an unusable response to a possibly completed token rotation.');
        }

        // A lost DB session between the remote rotation and final local write
        // is not authority to overwrite another credential generation.
        $this->assertDatabaseSessionId($plan['database_session_id']);

        return $this->withLockedTarget($recordId, function (Target $locked) use ($plan, $token): array {
            $intent = DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $locked->getKey())->first();
            $credential = $this->credential($locked);
            $metadata = $credential instanceof TargetCredential
                ? DB::table('wp_ai_bridge_credential_metadata')
                    ->where('credential_id', $credential->getKey())->first()
                : null;
            $config = $this->configuration((string) $locked->getKey());

            if ($intent === null || (string) $intent->id !== $plan['intent_id']
                || (string) $intent->credential_id !== $plan['credential_id']
                || (int) $intent->generation !== $plan['generation']
                || $credential?->getKey() !== $plan['credential_id']
                || $metadata === null || (int) $metadata->generation !== $plan['generation']
                || $this->hasRevocationIntent($locked)
                || ! hash_equals((string) $config->mcp_resource_url, $plan['resource_url'])
                || ! hash_equals((string) $config->oauth_token_url, $plan['token_url'])) {
                throw new WpAiBridgeTargetConnectionException('refresh_conflict',
                    'WordPress Target or credential changed during refresh; reconciliation is required.');
            }

            try {
                $secret = $this->vault->openCredential($locked, $credential);
            } catch (RuntimeException) {
                throw new WpAiBridgeTargetConnectionException('credential_unavailable',
                    'WordPress credential binding was lost during refresh.');
            }
            if (! hash_equals($secret['refresh_token'], $plan['refresh_token'])) {
                throw new WpAiBridgeTargetConnectionException('refresh_conflict',
                    'WordPress credential changed during the rotating refresh.');
            }

            $credential->forceFill([
                'encrypted_payload' => $this->vault->sealCredential(
                    $locked,
                    $plan['client_id'],
                    $plan['resource_url'],
                    $token['access_token'],
                    $token['refresh_token'],
                    $token['expires_at'],
                    $token['scopes'],
                ),
            ])->save();
            DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->getKey())->update([
                'access_expires_at' => $token['expires_at'],
                'refresh_expires_at' => $token['refresh_expires_at'],
                'refresh_due_at' => $token['refresh_due_at'],
                'generation' => $plan['generation'] + 1,
            ]);
            DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)->delete();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Connected,
                'last_error_code' => null,
                'last_success_at' => now(),
                'last_failure_code' => null,
            ])->save();

            return ['resource_url' => $plan['resource_url'], 'access_token' => $token['access_token']];
        });
    }

    /** @param array{intent_id:string,credential_id:string,generation:int,resource_url:string,refresh_token:string,client_id:string,scopes:list<string>,token_url:string,database_session_id:?int} $plan */
    private function recordRefreshFailure(string $recordId, array $plan, string $reason, bool $terminal = false): void
    {
        $this->withLockedTarget($recordId, function (Target $locked) use ($plan, $reason, $terminal): void {
            $intent = DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $locked->getKey())->first();
            if ($intent === null || (string) $intent->id !== $plan['intent_id']
                || (string) $intent->credential_id !== $plan['credential_id']
                || (int) $intent->generation !== $plan['generation']) {
                return;
            }
            if ($terminal) {
                DB::table('wp_ai_bridge_refresh_intents')->where('id', $intent->id)
                    ->update(['attempts' => 2, 'updated_at' => now()]);
            }
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Error,
                'last_error_code' => $reason,
                'last_failure_at' => now(),
                'last_failure_code' => $reason,
            ])->save();
        });
    }

    public function disconnect(Target $target): void
    {
        $id = (string) $target->getKey();
        /** @var array{credential_id:?string,tokens:list<string>,revocation_url:?string,database_session_id:?int} $plan */
        $plan = $this->withLockedTarget($id, function (Target $locked): array {
            if ($this->hasRefreshIntent($locked)) {
                // A rotating successor may exist remotely even when only the
                // old secret is retained. Revoking the old token is not proof
                // of successor revocation.
                throw new WpAiBridgeTargetConnectionException('refresh_pending',
                    'Unresolved WordPress refresh must be reconciled at WordPress before disconnecting.');
            }
            $flow = DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())->first();
            if ($flow !== null && $flow->consumed_at !== null) {
                throw new WpAiBridgeTargetConnectionException('callback_pending', 'An OAuth token exchange may still be running.');
            }
            $credential = $this->credential($locked);
            $tokens = [];
            $url = null;
            if ($credential instanceof TargetCredential) {
                try {
                    $secret = $this->vault->openCredential($locked, $credential);
                } catch (RuntimeException) {
                    throw new WpAiBridgeTargetConnectionException('credential_unavailable', 'The stored credential cannot be opened safely.');
                }
                $configuration = $this->configuration((string) $locked->getKey());
                if (! hash_equals((string) $configuration->mcp_resource_url, $secret['resource_url'])) {
                    throw new WpAiBridgeTargetConnectionException('target_changed', 'WordPress credential is bound to another remote resource.');
                }
                $url = (string) $configuration->oauth_revocation_url;
                $this->assertStoredSameOrigin($url, (string) $configuration->base_url);
                $tokens = array_values(array_unique([$secret['refresh_token'], $secret['access_token']]));
            }

            $intent = DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $locked->getKey())->first();
            if ($intent !== null && $intent->kind !== 'disconnect') {
                throw new WpAiBridgeTargetConnectionException('revocation_pending', 'Another revocation operation owns this Target.');
            }
            if ($intent === null) {
                DB::table('wp_ai_bridge_revocation_intents')->insert([
                    'id' => (string) Str::ulid(),
                    'target_record_id' => $locked->getKey(),
                    'kind' => 'disconnect',
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }

            DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())->delete();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Error,
                'last_error_code' => 'disconnect_pending',
                'connected_at' => null,
            ])->save();

            return [
                'credential_id' => $credential?->getKey(),
                'tokens' => $tokens,
                'revocation_url' => $url,
                'database_session_id' => $tokens === [] ? null : $this->databaseSessionId(),
            ];
        });

        foreach ($plan['tokens'] as $token) {
            try {
                $response = $this->http->postForm((string) $plan['revocation_url'], [
                    'token' => $token,
                    'client_assertion_type' => GatewayBridgeClientIdentity::ASSERTION_TYPE,
                    'client_assertion' => $this->identity->assertion((string) $plan['revocation_url']),
                ]);
                if ($response->status !== 200) {
                    throw new WpAiBridgeTargetConnectionException('revocation_failed', 'WordPress did not confirm credential revocation.');
                }
            } catch (OutboundRequestException $exception) {
                $this->recordFailure($id, $exception->reason);
                throw new WpAiBridgeTargetConnectionException($exception->reason, 'Remote credential revocation is incomplete.');
            } catch (WpAiBridgeTargetConnectionException $exception) {
                $this->recordFailure($id, $exception->reason);
                throw $exception;
            }
        }

        // On a lost MySQL session, do not erase the credential based on an
        // unverified remote outcome; retain the durable revocation intent.
        $this->assertDatabaseSessionId($plan['database_session_id']);
        $this->withLockedTarget($id, function (Target $locked) use ($plan): void {
            $intent = DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $locked->getKey())->first();
            $credential = $this->credential($locked);
            if ($intent === null || $intent->kind !== 'disconnect'
                || $credential?->getKey() !== $plan['credential_id']) {
                throw new WpAiBridgeTargetConnectionException('revocation_conflict', 'Credential or intent changed during revocation.');
            }
            $credential?->delete();
            DB::table('wp_ai_bridge_revocation_intents')->where('id', $intent->id)->delete();
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Disconnected,
                'last_error_code' => null,
                'connected_at' => null,
            ])->save();
        });
    }

    public function testConnection(Target $target): void
    {
        $this->requireWordpress($target);
        $configuration = $this->configuration((string) $target->getKey());
        try {
            $found = $this->discovery->discover($configuration->base_url);
            if (! hash_equals((string) $configuration->base_url, $found->baseUrl)) {
                throw new BridgeDiscoveryException('target_changed', 'Canonical WordPress origin changed.');
            }
        } catch (BridgeDiscoveryException $exception) {
            $this->recordDiscoveryFailure((string) $target->getKey(), $exception->reason);
            throw new WpAiBridgeTargetConnectionException($exception->reason, 'WordPress metadata check failed.');
        }

        $this->withLockedTarget((string) $target->getKey(), function (Target $locked) use ($configuration): void {
            $current = $this->configuration((string) $locked->getKey());
            if ($current->base_url !== $configuration->base_url) {
                throw new WpAiBridgeTargetConnectionException('target_changed', 'WordPress Target changed during the test.');
            }
            // A successful metadata probe is not proof that a pending remote
            // revocation was completed; retain its failure status and intent.
            $fields = [
                'last_tested_at' => now(),
                'last_success_at' => now(),
            ];
            if (! $this->hasRevocationIntent($locked) && ! $this->hasRefreshIntent($locked)) {
                $fields['last_error_code'] = null;
            }
            $locked->forceFill($fields)->save();
        });
    }

    private function ensureReadyForConnect(Target $target): void
    {
        if ($this->hasRefreshIntent($target)) {
            throw new WpAiBridgeTargetConnectionException('refresh_pending',
                'Reconcile the previous WordPress refresh before connecting.');
        }
        if ($this->hasRevocationIntent($target)) {
            throw new WpAiBridgeTargetConnectionException('revocation_pending', 'Finish revoking the prior credential first.');
        }
        if ($this->credential($target) instanceof TargetCredential) {
            throw new WpAiBridgeTargetConnectionException('already_connected', 'Disconnect the current credential before connecting again.');
        }
    }

    private function hasRefreshIntent(Target $target): bool
    {
        return DB::table('wp_ai_bridge_refresh_intents')
            ->where('target_record_id', $target->getKey())->exists();
    }

    private function hasRevocationIntent(Target $target): bool
    {
        return DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $target->getKey())->exists();
    }

    private function credential(Target $target): ?TargetCredential
    {
        return TargetCredential::query()
            ->where('target_record_id', $target->getKey())
            ->where('connector_type', 'wp_ai_bridge')
            ->where('purpose', self::PURPOSE)->first();
    }

    private function configuration(string $targetRecordId): object
    {
        $configuration = DB::table('wp_ai_bridge_target_configs')->where('target_record_id', $targetRecordId)->first();
        if ($configuration === null) {
            throw new WpAiBridgeTargetConnectionException('target_not_configured', 'WordPress Target configuration is missing.');
        }

        return $configuration;
    }

    private function requireWordpress(Target $target): void
    {
        if ($target->connector_type !== 'wp_ai_bridge') {
            throw new WpAiBridgeTargetConnectionException('unsupported_connector', 'Only WordPress Target credentials can be paired here.');
        }
    }

    /**
     * Short row-level transaction only. In particular, no discovery, token,
     * refresh, callback or revocation HTTP calls under this closure.
     *
     * @template T
     *
     * @param  callable(Target): T  $callback
     * @return T
     */
    private function withLockedTarget(string $recordId, callable $callback): mixed
    {
        return DB::transaction(function () use ($recordId, $callback): mixed {
            $target = Target::query()->whereKey($recordId)->lockForUpdate()->first();
            if (! $target instanceof Target) {
                throw new WpAiBridgeTargetConnectionException('target_not_found', 'The WordPress Target no longer exists.');
            }
            $this->requireWordpress($target);

            return $callback($target);
        });
    }

    private function failClaim(string $targetRecordId, string $stateHash, string $reason): void
    {
        $this->withLockedTarget($targetRecordId, function (Target $locked) use ($stateHash, $reason): void {
            $flow = DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())
                ->where('state_hash', $stateHash)->first();
            if ($flow === null || $flow->consumed_at === null) {
                return;
            }
            DB::table('wp_ai_bridge_oauth_flows')->where('id', $flow->id)->delete();
            $this->setFailure($locked, $reason, TargetConnectionState::ReconnectRequired);
        });
    }

    private function recordDiscoveryFailure(string $targetRecordId, string $reason): void
    {
        $this->withLockedTarget($targetRecordId, function (Target $locked) use ($reason): void {
            if ($this->credential($locked) instanceof TargetCredential
                || $this->hasRevocationIntent($locked)
                || DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $locked->getKey())->exists()) {
                // A failed metadata probe may not revoke or rebind an existing credential.
                $locked->forceFill([
                    'last_tested_at' => now(),
                    'last_failure_at' => now(),
                    'last_failure_code' => mb_substr($this->safeError($reason), 0, 64),
                ])->save();

                return;
            }
            $this->setFailure($locked, $reason, TargetConnectionState::Error);
        });
    }

    private function recordFailure(string $recordId, string $reason): void
    {
        $this->withLockedTarget($recordId,
            fn (Target $locked) => $this->setFailure($locked, $reason, TargetConnectionState::Error));
    }

    private function setFailure(Target $target, string $reason, TargetConnectionState $state): void
    {
        $reason = mb_substr($this->safeError($reason), 0, 64);
        $target->forceFill([
            'connection_state' => $state,
            'last_error_code' => $reason,
            'last_failure_at' => now(),
            'last_failure_code' => $reason,
            'connected_at' => null,
        ])->save();
    }

    /** @param array<string,mixed> $document
     * @return array{access_token:string,refresh_token:string,expires_at:DateTimeImmutable,refresh_expires_at:?DateTimeImmutable,refresh_due_at:DateTimeImmutable,scopes:list<string>}
     */
    private function parseToken(array $document): array
    {
        $accessToken = $document['access_token'] ?? null;
        $refreshToken = $document['refresh_token'] ?? null;
        $tokenType = $document['token_type'] ?? null;
        $expiresIn = $document['expires_in'] ?? null;
        $scope = $document['scope'] ?? null;
        $refreshTtl = $document['refresh_token_expires_in'] ?? null;
        if ($refreshTtl !== null && (! is_int($refreshTtl) || $refreshTtl < 1 || $refreshTtl > 315360000)) {
            throw new WpAiBridgeTargetConnectionException('invalid_token_response',
                'WordPress returned an invalid refresh-token lifetime.');
        }

        if (! is_string($accessToken) || $accessToken === '' || strlen($accessToken) > 8192
            || ! is_string($refreshToken) || $refreshToken === '' || strlen($refreshToken) > 8192
            || ! is_string($tokenType) || strcasecmp($tokenType, 'Bearer') !== 0
            || ! is_numeric($expiresIn) || (int) $expiresIn < 1 || (int) $expiresIn > 86400
            || ! is_string($scope)) {
            throw new WpAiBridgeTargetConnectionException('invalid_token_response', 'WordPress OAuth returned an unusable token response.');
        }
        $scopes = array_values(array_filter(preg_split('/ +/', trim($scope)) ?: [],
            static fn (string $value): bool => $value !== ''));
        if (! in_array((string) config('bridge.oauth.scope', 'mcp:use'), $scopes, true)
            || ! in_array((string) config('bridge.oauth.offline_scope', 'offline_access'), $scopes, true)) {
            throw new WpAiBridgeTargetConnectionException('invalid_token_response', 'WordPress OAuth did not grant the required scopes.');
        }

        $issuedAt = time();
        $halfAccessTtl = max(1, intdiv((int) $expiresIn, 2));
        $halfRefreshTtl = $refreshTtl === null ? $halfAccessTtl : max(1, intdiv($refreshTtl, 2));

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'expires_at' => new DateTimeImmutable('@'.($issuedAt + (int) $expiresIn)),
            'refresh_expires_at' => $refreshTtl === null ? null : new DateTimeImmutable('@'.($issuedAt + $refreshTtl)),
            'refresh_due_at' => new DateTimeImmutable('@'.($issuedAt + min($halfAccessTtl, $halfRefreshTtl))),
            'scopes' => $scopes,
        ];
    }

    /**
     * Verify the previously discovered endpoint still belongs to its stored
     * canonical origin before we send any bearer credential. No DNS lookup or
     * remote I/O is performed while holding the Target row lock. SafeHttpClient
     * independently validates and pins the approved destination at send time.
     */
    private function assertStoredSameOrigin(string $endpoint, string $baseUrl): void
    {
        $url = parse_url($endpoint);
        $base = parse_url($baseUrl);
        if (! is_array($url) || ! is_array($base)
            || strtolower((string) ($url['scheme'] ?? '')) !== 'https'
            || strtolower((string) ($base['scheme'] ?? '')) !== 'https'
            || (string) ($url['host'] ?? '') === ''
            || ! hash_equals(strtolower((string) $base['host']), strtolower((string) $url['host']))
            || (int) ($base['port'] ?? 443) !== (int) ($url['port'] ?? 443)
            || isset($url['user']) || isset($url['pass'])
            || isset($url['query']) || isset($url['fragment'])) {
            throw new WpAiBridgeTargetConnectionException('target_changed', 'WordPress remote credential endpoint no longer matches its approved origin.');
        }
    }

    private function requestedScope(): string
    {
        return trim((string) config('bridge.oauth.scope', 'mcp:use').' '.(string) config('bridge.oauth.offline_scope', 'offline_access'));
    }

    private function safeError(string $value): string
    {
        $safe = strtolower(preg_replace('/[^A-Za-z0-9_.-]+/', '_', $value) ?? 'error');

        return trim($safe, '_') !== '' ? trim($safe, '_') : 'error';
    }

    private function randomBase64Url(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    private function databaseSessionId(): ?int
    {
        if (! in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true)) {
            return null;
        }
        $row = DB::selectOne('SELECT CONNECTION_ID() AS connection_id');
        $id = is_object($row) ? (int) ($row->connection_id ?? 0) : 0;
        if ($id < 1) {
            throw new RuntimeException('Cannot establish durable WordPress revocation fencing.');
        }

        return $id;
    }

    private function assertDatabaseSessionId(?int $expected): void
    {
        if ($expected !== null && $this->databaseSessionId() !== $expected) {
            throw new RuntimeException('The DB session changed after remote revocation; retain the intent for recovery.');
        }
    }
}
