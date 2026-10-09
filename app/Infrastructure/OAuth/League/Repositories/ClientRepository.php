<?php

namespace App\Infrastructure\OAuth\League\Repositories;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\League\Entities\ClientEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final readonly class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(
        private ChatGptClientMetadata $metadata,
        private ClientProfileRegistry $profiles,
    ) {}

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $profile = $this->profiles->active($clientIdentifier);
        if ($profile === null) {
            return null;
        }

        $isChatGpt = $profile['strategy'] === 'cimd_private_key_jwt';

        return new ClientEntity(
            identifier: $clientIdentifier,
            name: $isChatGpt ? $this->metadata->clientName() : $profile['display_name'],
            redirectUris: $isChatGpt ? $this->metadata->redirectUris() : $profile['redirect_uris'],
        );
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        // The production grants must use private_key_jwt adapters. The League
        // shared-secret client path intentionally never authenticates ChatGPT.
        return false;
    }
}
