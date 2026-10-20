<?php

namespace App\Application\Mcp;

use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Models\User;

/**
 * One channel-aware pre-effect fence shared by WordPress and SSH.
 * Human Admin/CLI execution does not require an AI connection; only the
 * authenticated MCP HTTP routes do. Their request identities are installed
 * exclusively by RequireMcpAccessToken after OAuth resource validation.
 */
final readonly class McpDispatchAdmission
{
    public function __construct(private AccessTokenRepository $tokens) {}

    /** @phpstan-impure */
    public function allows(User $user): bool
    {
        $request = request();
        if (! $request->is('mcp', 'mcp/*')) {
            return true;
        }

        $tokenId = $request->attributes->get('oauth_access_token_id');
        $clientId = $request->attributes->get('oauth_client_id');
        $profileKey = $request->attributes->get('oauth_client_profile_key');
        $generation = $request->attributes->get('oauth_client_profile_generation');
        $userId = $request->attributes->get('oauth_user_id');
        $authenticatedUser = $request->attributes->get('oauth_user');
        $scopes = $request->attributes->get('oauth_scopes');

        if (! is_string($tokenId) || $tokenId === ''
            || ! is_string($clientId) || $clientId === ''
            || ! is_string($profileKey) || $profileKey === ''
            || ! is_int($generation) || $generation < 1
            || ! is_string($userId) || ! ctype_digit($userId)
            || ! $authenticatedUser instanceof User
            || (int) $userId !== (int) $user->getKey()
            || (int) $authenticatedUser->getKey() !== (int) $user->getKey()
            || ! is_array($scopes) || ! in_array((string) config('oauth.scope'), $scopes, true)) {
            return false;
        }

        return $this->tokens->authorizesDispatch(
            $tokenId, (int) $user->getKey(), $clientId, $profileKey, $generation,
        );
    }
}
