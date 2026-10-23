<?php

declare(strict_types=1);

use App\Infrastructure\OAuth\DcrClientRegistration;
use Illuminate\Contracts\Console\Kernel;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 3) {
    fwrite(STDERR, "usage: dcr_concurrent_registration_request.php <barrier> <ready>\n");
    exit(2);
}

[, $barrierPath, $readyPath] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
config()->set('oauth.dcr.registration_enabled', true);

try {
    if (! touch($readyPath)) {
        throw new RuntimeException('Worker could not report readiness.');
    }

    $deadline = microtime(true) + 10;
    while (! is_file($barrierPath)) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Timed out waiting for registration start barrier.');
        }
        usleep(1000);
    }

    $metadata = [
        'client_name' => 'ChatGPT',
        'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'client_secret_post',
    ];

    try {
        $registered = $app->make(DcrClientRegistration::class)->register($metadata);
        echo json_encode(['outcome' => 'registered', 'client_id' => $registered['client_id']], JSON_THROW_ON_ERROR);
    } catch (RuntimeException $exception) {
        if (! str_contains($exception->getMessage(), 'registration capacity is unavailable')) {
            throw $exception;
        }
        echo json_encode(['outcome' => 'capacity'], JSON_THROW_ON_ERROR);
    }
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
