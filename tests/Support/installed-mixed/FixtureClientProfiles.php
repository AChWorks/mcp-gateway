<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use RuntimeException;

/**
 * Installed-acceptance ONLY. Copied into the disposable package and registered
 * there, never loaded by the committed Gateway runtime.
 */
final class FixtureClientProfiles extends ServiceProvider
{
    public function register(): void
    {
        $path = env('MIXED_ACCEPTANCE_JWKS');
        if (! is_string($path) || ! is_file($path)) {
            throw new RuntimeException('Missing isolated acceptance JWKS.');
        }
        $jwks = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        foreach (['acceptance', 'ungranted', 'never_granted'] as $key) {
            config()->set('oauth.client_profiles.'.$key, [
                'client_id' => 'https://mixed-sdk.example.test/'.match ($key) {
                    'acceptance' => 'allowed', 'ungranted' => 'ungranted', default => 'never-granted'
                },
                'display_name' => 'Disposable installed MCP SDK '.$key,
                'strategy' => 'pinned_private_key_jwt',
                'enabled' => true,
                'redirect_uris' => ['https://11.22.33.45/fixture/callback'],
                'jwks' => $jwks,
            ]);
        }
    }
}
