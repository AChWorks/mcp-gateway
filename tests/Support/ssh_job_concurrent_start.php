<?php

declare(strict_types=1);

use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Str;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 4 || ! in_array($argv[2], ['a', 'b'], true)) {
    fwrite(STDERR, "usage: ssh_job_concurrent_start.php <private-test-barrier> <a|b> <numeric-user-id>\n");
    exit(2);
}

[, $directory, $workerId, $userId] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

// No socket or remote command: this fake returns no dialable IPs. Importantly,
// entering the policy happens AFTER the admission DB transaction commits;
// hold that pre-side-effect probe until the parent has checked both entrants.
$app->bind(SshDialAddressPolicy::class,
    static fn (): SshDialAddressPolicy => new class($directory, $workerId) implements SshDialAddressPolicy
    {
        public function __construct(private string $directory, private string $workerId) {}

        public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
        {
            file_put_contents($this->directory.'/probe-'.$this->workerId, 'pre-dispatch');
            $limit = microtime(true) + 10;
            while (! is_file($this->directory.'/release')) {
                if (microtime(true) >= $limit) {
                    throw new RuntimeException('SSH fixture probe was not released in time.');
                }
                usleep(10000);
            }

            throw new SshTargetConnectionException('egress_denied');
        }
    });

try {
    $user = User::query()->findOrFail((int) $userId);
    $target = Target::query()->where('target_id', 'ssh-job-admission-race')->firstOrFail();
    file_put_contents($directory.'/ready-'.$workerId, 'ready');
    $limit = microtime(true) + 10;
    while (! is_file($directory.'/go')) {
        if (microtime(true) >= $limit) {
            throw new RuntimeException('SSH admission fixture was not started.');
        }
        usleep(10000);
    }
    $response = $app->make(SshJobMcpToolHandlers::class)->start(
        $user, $target->target_id, hash('sha256', 'admission-worker-'.$workerId),
        (string) Str::uuid(), 'echo only-once-'.$workerId, 16,
    );
    file_put_contents($directory.'/result-'.$workerId,
        json_encode($response, JSON_THROW_ON_ERROR));
    echo json_encode($response, JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
