<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use App\Infrastructure\OAuth\League\Entities\ClientEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final readonly class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(private ChatGptClientMetadata $metadata) {}

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        if (! hash_equals((string) config('oauth.client.id'), $clientIdentifier)) {
            return null;
        }

        return new ClientEntity(
            identifier: $clientIdentifier,
            name: $this->metadata->clientName(),
            redirectUris: $this->metadata->redirectUris(),
        );
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        // The production grants must use private_key_jwt adapters. The League
        // shared-secret client path intentionally never authenticates ChatGPT.
        return false;
    }
}
