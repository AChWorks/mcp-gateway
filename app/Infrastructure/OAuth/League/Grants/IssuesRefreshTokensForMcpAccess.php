<?php

namespace App\Infrastructure\OAuth\League\Grants;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;

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
