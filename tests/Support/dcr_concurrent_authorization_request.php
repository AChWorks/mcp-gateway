<?php

declare(strict_types=1);

use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use Illuminate\Contracts\Console\Kernel;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 6) {
    fwrite(STDERR, "usage: dcr_concurrent_authorization_request.php <client> <user_id> <ready> <barrier> <entered>\n");
    exit(2);
}

[, $clientId, $userId, $readyPath, $barrierPath, $enteredPath] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

try {
    // Reproduce the stale positive client check already performed by the OAuth
    // controller before it invokes the authorization store.
    $preflight = $app->make(ClientProfileRegistry::class)->active($clientId);
    if ($preflight === null || ! is_string($preflight['key'] ?? null)) {
        throw new RuntimeException('Authorization race fixture must start with an active DCR client.');
    }
    if (! touch($readyPath)) {
        throw new RuntimeException('Authorization race fixture could not signal readiness.');
    }

    $deadline = microtime(true) + 10;
    while (! is_file($barrierPath)) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Timed out waiting for the authorization-race barrier.');
        }

        usleep(1000);
    }

    if (! touch($enteredPath)) {
        throw new RuntimeException('Authorization race fixture could not signal entry.');
    }

    try {
        $grantId = $app->make(OAuthAuthorizationStore::class)->approve(
            (int) $userId, (string) $clientId, (string) config('oauth.resource'), ['mcp'],
        );

        echo json_encode(['result' => 'approved', 'grant_id' => $grantId], JSON_THROW_ON_ERROR);
    } catch (RuntimeException $exception) {
        if (! str_starts_with($exception->getMessage(), 'OAuth client profile')
            && ! str_starts_with($exception->getMessage(), 'OAuth client registration')) {
            throw $exception;
        }

        echo json_encode(['result' => 'refused'], JSON_THROW_ON_ERROR);
    }
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
