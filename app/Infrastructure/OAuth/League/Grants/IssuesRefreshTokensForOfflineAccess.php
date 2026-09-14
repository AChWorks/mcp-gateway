<?php

namespace App\Infrastructure\OAuth\League\Grants;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;

trait IssuesRefreshTokensForOfflineAccess
{
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        foreach ($accessToken->getScopes() as $scope) {
            if ($scope->getIdentifier() === (string) config('oauth.offline_scope')) {
                return parent::issueRefreshToken($accessToken);
            }
        }

        return null;
    }
}
