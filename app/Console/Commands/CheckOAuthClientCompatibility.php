<?php

namespace App\Console\Commands;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use Firebase\JWT\JWK;
use Illuminate\Console\Command;

final class CheckOAuthClientCompatibility extends Command
{
    protected $signature = 'gateway:oauth-client-check {--refresh : Ignore cached client metadata/JWKS}';

    protected $description = 'Validate the configured ChatGPT OAuth client metadata and JWKS contract.';

    public function handle(ChatGptClientMetadata $client): int
    {
        try {
            $refresh = (bool) $this->option('refresh');
            $metadata = $client->metadata($refresh);
            $jwks = $client->jwks($refresh);
            $parsedKeys = JWK::parseKeySet($jwks);

            $this->line('[OK] Client ID: '.(string) $metadata['client_id']);
            $this->line('[OK] Client name: '.(string) $metadata['client_name']);
            $this->line('[OK] Token auth: private_key_jwt / RS256');
            $this->line('[OK] Redirect URIs: '.count((array) $metadata['redirect_uris']));
            $this->line('[OK] Usable RS256 signing keys: '.count($parsedKeys));

            return self::SUCCESS;
        } catch (\Throwable $exception) {
            $this->error('OAuth client compatibility check failed: '.$exception->getMessage());

            return self::FAILURE;
        }
    }
}
