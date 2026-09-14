<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\League\Entities\ScopeEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final class ScopeRepository implements ScopeRepositoryInterface
{
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return in_array($identifier, (array) config('oauth.scopes'), true)
            ? new ScopeEntity($identifier)
            : null;
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        $supported = (array) config('oauth.scopes');

        return array_values(array_filter(
            $scopes,
            static fn (ScopeEntityInterface $scope): bool => in_array($scope->getIdentifier(), $supported, true),
        ));
    }
}
