<?php

declare(strict_types=1);

use App\Application\Sites\SiteCheckOperationService;
use App\Domain\Sites\SiteCheckOperation;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 4) {
    fwrite(STDERR, "usage: site_check_concurrent_action.php <payload> <barrier> <ready>\n");
    exit(2);
}

[, $payloadPath, $barrierPath, $readyPath] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$kernel = $app->make(Kernel::class);
$kernel->bootstrap();

try {
    $payload = json_decode((string) file_get_contents($payloadPath), true, flags: JSON_THROW_ON_ERROR);
    if (! is_array($payload)) {
        throw new RuntimeException('Concurrency payload is invalid.');
    }

    $app->instance(DnsResolver::class, new class implements DnsResolver
    {
        public function resolve(string $host): array
        {
            return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
        }
    });

    Http::preventStrayRequests();
    Http::fake(function (Request $request) use ($payload) {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);

        if ($path === '/.well-known/oauth-protected-resource') {
            $log = is_string($payload['check_log'] ?? null) ? $payload['check_log'] : null;
            if ($log !== null) {
                file_put_contents($log, $host."\n", FILE_APPEND | LOCK_EX);
            }

            $delay = max(0, (int) ($payload['delay_us'] ?? 0));
            if ($delay > 0) {
                usleep($delay);
            }

            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
                'resource_name' => 'WP AI Bridge',
            ], 200);
        }

        if ($path === '/.well-known/oauth-authorization-server') {
            return Http::response([
                'issuer' => $base,
                'authorization_endpoint' => $base.'/wp-ai-bridge/oauth/authorize',
                'token_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
                'revocation_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'scopes_supported' => ['mcp:use', 'offline_access'],
            ], 200);
        }

        return Http::response([], 404);
    });

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

    $user = User::query()->find((int) ($payload['user_id'] ?? 0));
    $operation = SiteCheckOperation::query()->find((string) ($payload['operation_id'] ?? ''));
    if (! $user instanceof User || ! $operation instanceof SiteCheckOperation) {
        throw new RuntimeException('Concurrency fixture state is missing.');
    }

    app(SiteCheckOperationService::class)->advance($user, $operation);

    echo json_encode([
        'ok' => true,
        'operation_id' => (string) $operation->getKey(),
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
