<?php

declare(strict_types=1);

use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 7 || ! in_array($argv[2], ['renew', 'start'], true)) {
    fwrite(STDERR, "usage: ssh_job_dispatch_race.php <barrier> <renew|start> <user-id> <target-id> <job-id> <lease-expiry>\n");
    exit(2);
}
[, $directory, $mode, $userId, $targetId, $jobId, $expires] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

try {
    $user = User::query()->findOrFail((int) $userId);
    if ($mode === 'renew') {
        // Simulate the old expiry-boundary worker's independently captured
        // pre-expiry clock, even while another process crosses the boundary.
        // A real MariaDB row lock and transaction still govern admission.
        Carbon::setTestNow(Carbon::parse($expires)->subSecond());
        DB::listen(static function (QueryExecuted $query) use ($directory): void {
            $sql = strtolower($query->sql);
            if (str_contains($sql, 'ssh_command_jobs') && str_contains($sql, 'for update')
                && ! is_file($directory.'/renew-job-locked')) {
                file_put_contents($directory.'/renew-job-locked', 'holding-job-and-user');
                $limit = microtime(true) + 12;
                while (! is_file($directory.'/release-renew')) {
                    if (microtime(true) >= $limit) {
                        throw new RuntimeException('MariaDB dispatch renewal barrier expired.');
                    }
                    usleep(10000);
                }
            }
        });
        file_put_contents($directory.'/ready-renew', 'ready');
        $gate = new ReflectionMethod(SshJobCoordinator::class, 'reserveDispatchLease');
        $renewed = $gate->invoke($app->make(SshJobCoordinator::class), $jobId);
        file_put_contents($directory.'/result-renew', json_encode(['renewed' => $renewed], JSON_THROW_ON_ERROR));
    } else {
        $app->bind(SshDialAddressPolicy::class,
            static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
            {
                public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
                {
                    throw new SshTargetConnectionException('egress_denied');
                }
            });
        file_put_contents($directory.'/ready-start', 'ready');
        $limit = microtime(true) + 12;
        while (! is_file($directory.'/go-start')) {
            if (microtime(true) >= $limit) {
                throw new RuntimeException('MariaDB fresh admission barrier expired.');
            }
            usleep(10000);
        }
        $target = Target::query()->where('target_id', $targetId)->firstOrFail();
        file_put_contents($directory.'/start-entered', 'attempting');
        $response = $app->make(SshJobMcpToolHandlers::class)->start(
            $user, $target->target_id, hash('sha256', 'dispatch-boundary-start-client'),
            (string) Str::uuid(), 'echo must-not-double-admit', 16,
        );
        file_put_contents($directory.'/result-start', json_encode($response, JSON_THROW_ON_ERROR));
    }
} catch (Throwable $exception) {
    file_put_contents($directory.'/error-'.$mode,
        $exception::class.': '.$exception->getMessage());
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
