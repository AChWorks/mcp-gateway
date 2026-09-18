<?php

namespace App\Infrastructure\OAuth\League\Grants;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;

/**
 * The fixed ChatGPT client currently authorizes the required MCP resource with
 * scope=mcp. Keep that approved authorization refreshable so short-lived access
 * tokens can rotate without forcing the operator through another consent flow.
 */
trait IssuesRefreshTokensForMcpAccess
{
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        foreach ($accessToken->getScopes() as $scope) {
            if ($scope->getIdentifier() === (string) config('oauth.scope')) {
                return parent::issueRefreshToken($accessToken);
            }
        }

        return null;
    }
}
