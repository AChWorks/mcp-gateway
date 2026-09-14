<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

final readonly class BridgeDiscovery
{
    public function __construct(
        public string $baseUrl,
        public string $resourceUrl,
        public string $issuerUrl,
        public string $authorizationUrl,
        public string $tokenUrl,
        public string $revocationUrl,
    ) {
    }
}
