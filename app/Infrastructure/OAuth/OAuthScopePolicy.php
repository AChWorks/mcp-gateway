<?php

namespace App\Infrastructure\OAuth;

use League\OAuth2\Server\Exception\OAuthServerException;

final class OAuthScopePolicy
{
    public function assertAllowed(mixed $scope): void
    {
        if ($scope === null || $scope === '') {
            return;
        }

        if (! is_string($scope) || strlen($scope) > 256) {
            throw OAuthServerException::invalidScope('');
        }

        $requested = preg_split('/\s+/', trim($scope), -1, PREG_SPLIT_NO_EMPTY);
        if (! is_array($requested) || $requested === []) {
            return;
        }

        $requested = array_values(array_unique($requested));
        $supported = array_values(array_map('strval', (array) config('oauth.scopes')));
        $required = (string) config('oauth.scope');

        foreach ($requested as $identifier) {
            if (! in_array($identifier, $supported, true)) {
                throw OAuthServerException::invalidScope($scope);
            }
        }

        if (! in_array($required, $requested, true)) {
            throw OAuthServerException::invalidScope($scope);
        }
    }
}
