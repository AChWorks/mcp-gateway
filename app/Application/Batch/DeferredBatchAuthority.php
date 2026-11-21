<?php

namespace App\Application\Batch;

use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/** Captures the middleware-proven grant without copying bearer/refresh tokens. */
final readonly class DeferredBatchAuthority
{
    public function __construct(
        private AccessTokenRepository $tokens,
        private ClientProfileRegistry $profiles,
    ) {}

    /** @return array<string,mixed> */
    public function captureMcp(User $user, Request $request): array
    {
        $client = $request->attributes->get('oauth_client_id');
        $profile = $request->attributes->get('oauth_client_profile_key');
        $generation = $request->attributes->get('oauth_client_profile_generation');
        $tokenId = $request->attributes->get('oauth_access_token_id');
        if (! is_string($client) || $client === '' || ! is_string($profile) || $profile === ''
            || ! is_int($generation) || $generation < 1
            || ! is_string($tokenId) || $tokenId === ''
            || $request->attributes->get('oauth_user_id') !== (string) $user->getKey()
            || ! $this->tokens->authorizesDispatch($tokenId, (int) $user->getKey(), $client, $profile, $generation)) {
            throw new RuntimeException('MCP Batch requires a currently valid, middleware-verified token and consent.');
        }
        $authorization = DB::table('oauth_access_tokens')
            ->where('id', $tokenId)->where('user_id', $user->getKey())
            ->whereNull('revoked_at')->value('authorization_id');
        if (! is_string($authorization) || $authorization === '') {
            throw new RuntimeException('MCP authorization identity is missing.');
        }

        return [
            'source_channel' => 'mcp', 'client_id' => $client,
            'client_identity_hash' => hash('sha256', $profile."\0".$client),
            'client_profile_key' => $profile,
            'client_profile_generation' => $generation,
            'authorization_id' => $authorization,
            'resource_hash' => hash('sha256', (string) config('oauth.resource')),
        ];
    }

    /** @return array<string,mixed> */
    public function captureWeb(User $user, Request $request): array
    {
        if ($request->user()?->getAuthIdentifier() !== $user->getAuthIdentifier()
            || ! $user->access_enabled) {
            throw new RuntimeException('Web Batch must originate from an authenticated user session.');
        }

        return [
            'source_channel' => 'web', 'client_id' => null,
            'client_identity_hash' => hash('sha256', 'human-web'),
            'client_profile_key' => null, 'client_profile_generation' => null,
            'authorization_id' => null, 'resource_hash' => null,
        ];
    }

    public function allows(object $batch, User $user): bool
    {
        if (! $user->access_enabled || (int) $user->getKey() !== (int) $batch->actor_user_id) {
            return false;
        }
        if ($batch->source_channel === 'web') {
            return $batch->client_id === null && $batch->authorization_id === null
                && $batch->client_profile_key === null
                && $batch->client_identity_hash === hash('sha256', 'human-web');
        }
        if ($batch->source_channel !== 'mcp' || ! $user->ai_access_enabled
            || ! is_string($batch->client_id) || $batch->client_id === ''
            || ! is_string($batch->client_profile_key) || $batch->client_profile_key === ''
            || ! is_string($batch->authorization_id) || $batch->authorization_id === ''
            || ! is_string($batch->resource_hash)
            || ! hash_equals($batch->resource_hash, hash('sha256', (string) config('oauth.resource')))
            || ! hash_equals((string) $batch->client_identity_hash,
                hash('sha256', $batch->client_profile_key."\0".$batch->client_id))
            || ! $this->profiles->authorizes(
                $batch->client_id, $batch->client_profile_key, (int) $batch->client_profile_generation,
            )) {
            return false;
        }
        $authorization = DB::table('oauth_authorizations')
            ->where('id', $batch->authorization_id)
            ->where('user_id', $batch->actor_user_id)
            ->where('client_id', $batch->client_id)
            ->where('client_profile_key', $batch->client_profile_key)
            ->where('client_profile_generation', $batch->client_profile_generation)
            ->where('resource', (string) config('oauth.resource'))
            ->whereNull('revoked_at')->first();
        if ($authorization === null || ! hash_equals((string) $authorization->resource_hash, $batch->resource_hash)) {
            return false;
        }
        $scopes = json_decode((string) $authorization->scopes, true);

        return is_array($scopes) && in_array((string) config('oauth.scope'), $scopes, true);
    }
}
