<?php

namespace App\Infrastructure\OAuth\League\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;

final readonly class ClientEntity implements ClientEntityInterface
{
    /** @param list<string> $redirectUris */
    public function __construct(
        private string $identifier,
        private string $name,
        private array $redirectUris,
    ) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->name;
    }

    /** @return list<string> */
    public function getRedirectUri(): array
    {
        return $this->redirectUris;
    }

    public function isConfidential(): bool
    {
        return true;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, ['authorization_code', 'refresh_token'], true);
    }
}
