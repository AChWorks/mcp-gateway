<?php

declare(strict_types=1);

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 5) {
    fwrite(STDERR, "usage: oauth_concurrent_token_request.php <payload> <jwk> <barrier> <ready>\n");
    exit(2);
}

[, $payloadPath, $jwkPath, $barrierPath, $readyPath] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';

try {
    $payload = json_decode((string) file_get_contents($payloadPath), true, flags: JSON_THROW_ON_ERROR);
    $clientJwk = json_decode((string) file_get_contents($jwkPath), true, flags: JSON_THROW_ON_ERROR);

    if (! is_array($payload) || ! is_array($clientJwk)) {
        throw new RuntimeException('Concurrency fixture input is invalid.');
    }

    $metadata = [
        'client_id' => 'https://chatgpt.com/oauth/client.json',
        'client_uri' => 'https://chatgpt.com/',
        'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
        'token_endpoint_auth_method' => 'private_key_jwt',
        'grant_types' => ['authorization_code', 'refresh_token'],
        'response_types' => ['code'],
        'client_name' => 'ChatGPT',
        'token_endpoint_auth_signing_alg' => 'RS256',
        'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
    ];
    $mock = new MockHandler([
        new PsrResponse(200, ['Content-Type' => 'application/json'], json_encode($metadata, JSON_THROW_ON_ERROR)),
        new PsrResponse(200, ['Content-Type' => 'application/json'], json_encode(['keys' => [$clientJwk]], JSON_THROW_ON_ERROR)),
    ]);
    $app->instance(
        ChatGptClientMetadata::class,
        new ChatGptClientMetadata(new Client(['handler' => HandlerStack::create($mock)])),
    );

    if (! touch($readyPath)) {
        throw new RuntimeException('Concurrency worker could not signal readiness.');
    }

    $deadline = microtime(true) + 10;
    while (! is_file($barrierPath)) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Concurrency worker timed out waiting for the start barrier.');
        }

        usleep(1000);
    }

    $issuer = (string) config('oauth.issuer');
    $host = (string) (parse_url($issuer, PHP_URL_HOST) ?: '127.0.0.1');
    $scheme = (string) (parse_url($issuer, PHP_URL_SCHEME) ?: 'http');
    $port = parse_url($issuer, PHP_URL_PORT);
    $server = [
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_HOST' => $host,
        'HTTPS' => $scheme === 'https' ? 'on' : 'off',
    ];
    if (is_int($port)) {
        $server['SERVER_PORT'] = (string) $port;
    }

    $request = Request::create('/oauth/token', 'POST', $payload, [], [], $server);
    $kernel = $app->make(Kernel::class);
    $response = $kernel->handle($request);
    $kernel->terminate($request, $response);

    echo json_encode([
        'status' => $response->getStatusCode(),
        'body' => json_decode((string) $response->getContent(), true),
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
