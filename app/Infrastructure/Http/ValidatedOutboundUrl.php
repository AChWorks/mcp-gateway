<?php

namespace App\Infrastructure\Http;

final readonly class ValidatedOutboundUrl
{
    /** @param list<string> $addresses */
    public function __construct(
        public string $url,
        public string $host,
        public int $port,
        public array $addresses,
    ) {
    }

    public function pinnedAddress(): string
    {
        return $this->addresses[0];
    }
}
