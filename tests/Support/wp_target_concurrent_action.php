<?php

declare(strict_types=1);

use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\DnsResolver;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 5 || ! in_array($argv[1], ['refresh', 'disconnect'], true)) {
    fwrite(STDERR, "usage: wp_target_concurrent_action.php <refresh|disconnect> <directory> <worker-id> <hold-remote-flag>\n");
    exit(2);
}

[, $action, $directory, $workerId, $holdRemote] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');

// The synthetic issuer never receives external requests. Each worker has its
// own DB connection, fake HTTP transport, and independent process lifetime.
$app->instance(DnsResolver::class, new class implements DnsResolver
{
    public function resolve(string $host): array
    {
        return $host === 'race.example.test' ? ['1.1.1.1'] : [];
    }
});
Http::preventStrayRequests();
Http::fake(static function (Request $request) use ($directory, $workerId, $holdRemote) {
    if (DB::transactionLevel() !== 0) {
        throw new RuntimeException('WordPress HTTP sent under a DB transaction.');
    }
    $data = $request->data();
    $grantType = $data['grant_type'] ?? null;
    if ($grantType === 'refresh_token') {
        file_put_contents($directory.'/remote-'.$workerId, 'refresh');
        if ($holdRemote === 'yes') {
            $deadline = microtime(true) + 9;
            while (! is_file($directory.'/release')) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Unreleased remote refresh fixture.');
                }
                usleep(10000);
            }
        }

        return Http::response([
            'access_token' => 'race-rotated-access',
            'refresh_token' => 'race-rotated-refresh',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token_expires_in' => 7200,
            'scope' => 'mcp:use offline_access',
        ]);
    }
    if (str_ends_with($request->url(), '/oauth/revoke')) {
        file_put_contents($directory.'/remote-'.$workerId, 'revoke');

        return Http::response('', 200);
    }

    throw new RuntimeException('Unexpected outbound request in WP concurrency fixture.');
});

if (! touch($directory.'/ready-'.$workerId)) {
    throw new RuntimeException('Could not signal worker readiness.');
}

try {
    $target = Target::query()->where('target_id', 'race')->firstOrFail();
    $service = $app->make(WpAiBridgeTargetConnectionService::class);
    $result = $action === 'refresh'
        ? $service->accessToken($target)
        : (static function () use ($service, $target): string {
            $service->disconnect($target);

            return 'disconnected';
        })();

    echo json_encode(['status' => 'ok', 'result' => $result], JSON_THROW_ON_ERROR);
} catch (WpAiBridgeTargetConnectionException $exception) {
    echo json_encode(['status' => 'blocked', 'reason' => $exception->reason], JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
