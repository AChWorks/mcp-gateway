<?php

namespace App\Infrastructure\OAuth;

final readonly class SiteOAuthFlowContext
{
    public function __construct(
        public string $siteRecordId,
        public string $clientId,
        public string $redirectUri,
        public string $resourceUrl,
        public string $issuerUrl,
        public string $tokenUrl,
        public string $revocationUrl,
        public string $codeVerifier,
    ) {
    }
}
