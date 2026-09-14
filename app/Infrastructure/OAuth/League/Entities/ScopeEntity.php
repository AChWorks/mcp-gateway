<?php

namespace App\Infrastructure\OAuth\League\Entities;

use JsonSerializable;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

final class ScopeEntity implements JsonSerializable, ScopeEntityInterface
{
    use EntityTrait;

    public function __construct(string $identifier)
    {
        $this->setIdentifier($identifier);
    }

    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
