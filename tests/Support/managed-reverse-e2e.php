<?php

/**
 * Disposable GitHub Actions acceptance harness (not a production endpoint).
 * Owns one SQLite DB, one independently pinned Target sshd, one controlled
 * host manifest and one exact generated single-command onboarding operation.
 */
declare(strict_types=1);

use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchBinding;
use App\Application\Batch\TargetBatchCoordinator;
use App\Application\Batch\TargetBatchWorker;
use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseHostReadiness;
use App\Application\Targets\SshManagedReverseInstallCommand;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshVerificationState;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Http\Controllers\Admin\SshManagedReverseController;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use phpseclib4\Net\SFTP;

require dirname(__DIR__, 2).'/vendor/autoload.php';
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$mode = $argv[1] ?? '';
$root = getenv('MANAGED_REVERSE_E2E_DIR');
try {
    if (getenv('GITHUB_ACTIONS') !== 'true' || $root === false || ! is_dir($root)) {
        throw new RuntimeException('Only the isolated GitHub Actions acceptance fixture may run.');
    }

    $targetId = 'ci-managed-reverse';
    $targetPort = (int) getenv('MANAGED_REVERSE_TARGET_PORT');
    $controlPort = (int) getenv('MANAGED_REVERSE_CONTROL_PORT');
    // The root-owned manifest deliberately exposes the verified PUBLIC control
    // host identity; the root-only SSHD key files are never opened by Laravel.
    $manifest = json_decode(
        (string) file_get_contents('/etc/mcp-gateway-reverse/manifest.json'),
        true, 16, JSON_THROW_ON_ERROR,
    );
    $controlPin = (string) $manifest['control_host_key'];

    if ($mode === 'enroll') {
        $pin = trim((string) file_get_contents($root.'/target-host.pub'));
        $pin = implode(' ', array_slice(preg_split('/\s+/', $pin), 0, 2));
        SshManagedReverseGateway::query()->create([
            'id' => 1,
            'enabled' => true,
            'control_host' => '127.0.0.1',
            'control_port' => $controlPort,
            'control_user' => 'mcp-reverse',
            'control_host_key' => $controlPin,
        ]);

        $result = app(SshManagedReverseEnrollmentService::class)->begin(
            $targetId, 'Disposable E2E Target',
            '8.8.8.8', $targetPort, 'deploy.prod', $pin,
        );
        $enrollment = $result['enrollment'];
        $command = app(SshManagedReverseInstallCommand::class)
            ->command($enrollment, $result['token']);
        file_put_contents($root.'/one-command.sh', $command."\n", LOCK_EX);
        file_put_contents($root.'/enrollment-id', (string) $enrollment->id, LOCK_EX);
        echo "One-use Target command generated from application state (not logged).\n";
        exit(0);
    }

    $target = Target::query()->where('target_id', $targetId)->firstOrFail();
    if ($mode === 'reissue') {
        $original = SshManagedReverseEnrollment::query()
            ->where('target_record_id', $target->getKey())->sole();
        $oldId = (string) $original->getKey();
        $oldPort = $original->listener_port;
        $verified = $target->connection_state->value === 'connected';
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $oldCipher = (string) $credential->encrypted_payload;
        $oldBinding = SshTargetBinding::hash($target, $target->sshConfig);
        $next = app(SshManagedReverseEnrollmentService::class)->reissue($original);
        $enrollment = $next['enrollment'];
        if ($enrollment->id === $oldId || $enrollment->target_record_id !== $target->getKey()
            || $enrollment->listener_port === $oldPort || $enrollment->state !== 'pending') {
            throw new RuntimeException('Owner reissue reused prior Target-side identity or listener.');
        }
        $command = app(SshManagedReverseInstallCommand::class)
            ->command($enrollment, $next['token']);
        if (! str_contains($command, (string) $enrollment->id)) {
            throw new RuntimeException('Generated reissue command omits rotated enrollment identity.');
        }
        $target->refresh();
        if (! hash_equals($oldCipher, (string) $credential->fresh()->encrypted_payload)
            || SshTargetBinding::hash($target, $target->sshConfig) === $oldBinding) {
            throw new RuntimeException('Reissue changed the login credential or failed to fence the old transport.');
        }
        if ($verified) {
            if ($original->login_public_key !== '' || $enrollment->login_public_key !== ''
                || str_contains($command, '--target-user')
                || $target->connection_state->value !== 'connected') {
                throw new RuntimeException('Verified login was unexpectedly converted back to bootstrap provisioning.');
            }
            file_put_contents($root.'/verified-login-cipher-sha', hash('sha256', $oldCipher), LOCK_EX);
        }
        file_put_contents($root.'/one-command.sh', $command."\n", LOCK_EX);
        file_put_contents($root.'/enrollment-id', (string) $enrollment->id, LOCK_EX);
        echo $verified
            ? "PASS: verified enrollment reissued transport-only, preserving authorization and exact login ciphertext.\n"
            : "PASS: uncertain claimed enrollment reissued with stable Target, new installer namespace and fenced old port.\n";
        exit(0);
    }

    $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
    $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->firstOrFail();
    $vault = app(SshTargetVault::class);
    $material = $vault->open($target, $config, $credential);
    $policy = app(SshReverseRoutePolicy::class);
    $route = $policy->forTarget($target);
    if (! $route) {
        throw new RuntimeException('Expected approved, Target-bound reverse route.');
    }
    $transport = app(SshVerifiedTransport::class);
    $pin = SshHostKeyPin::fromLine($config->pinned_host_key);

    if ($mode === 'readiness' || $mode === 'readiness-stopped') {
        $health = app(SshManagedReverseHostReadiness::class)->assess(
            SshManagedReverseGateway::query()->findOrFail(1),
        );
        $expected = $mode === 'readiness' ? 'Ready' : 'Degraded';
        if ($health['state'] !== $expected) {
            throw new RuntimeException('Expected '.$expected.' control-host readiness, got '.$health['state'].': '.$health['reason']);
        }
        echo 'PASS: bounded pinned control-host readiness state '.$health['state'].".\n";
        exit(0);
    }

    if ($mode === 'job') {
        $owner = User::query()->create([
            'name' => 'Disposable managed retained Job',
            'email' => 'managed-job-'.bin2hex(random_bytes(6)).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
        $client = hash('sha256', 'managed-reverse-e2e-job');
        $tools = app(SshJobMcpToolHandlers::class);
        $started = $tools->start(
            $owner, $target->target_id, $client, (string) Str::uuid(),
            'printf managed_real_retained_job_ok', 60,
        );
        if (! ($started['ok'] ?? false)) {
            throw new RuntimeException('Managed SSH Job launch failed: '.json_encode($started));
        }
        $id = $started['result']['job_id'];
        if (DB::table('ssh_command_jobs')->where('id', $id)->value('target_binding_hash')
            !== SshTargetBinding::hash($target, $config)) {
            throw new RuntimeException('Managed Job does not retain its exact route binding.');
        }
        $status = null;
        for ($attempt = 0; $attempt < 30; $attempt++) {
            $status = $tools->status($owner, $target->target_id, $client, $id);
            if (($status['result']['status'] ?? null) === 'completed'
                && ($status['result']['exit_code'] ?? null) === 0) {
                break;
            }
            sleep(2);
        }
        if (($status['result']['status'] ?? null) !== 'completed'
            || ($status['result']['exit_code'] ?? null) !== 0) {
            throw new RuntimeException('Managed retained Job failed or incomplete: '.json_encode($status));
        }
        $output = $tools->output($owner, $target->target_id, $client, $id, 'stdout', 0, 16384);
        if (! ($output['ok'] ?? false)
            || base64_decode((string) ($output['result']['data'] ?? ''), true) !== 'managed_real_retained_job_ok') {
            throw new RuntimeException('Managed retained Job output mismatch.');
        }
        echo "PASS: newly enrolled managed Reverse SSH executes pinned, retained Job with durable completion and output.\n";
        exit(0);
    }

    if ($mode === 'authority-aba') {
        $job = DB::table('ssh_command_jobs')->where('target_record_id', $target->getKey())
            ->where('status', 'completed')->sole();
        $owner = User::query()->findOrFail($job->user_id);
        Auth::guard()->setUser($owner);
        $oldBinding = SshTargetBinding::hash($target, $config);
        $oldBatch = app(TargetBatchBinding::class)->hash($target);
        $oldEpoch = $target->transport_revision;
        $oldCipher = (string) $credential->encrypted_payload;
        $keyPath = $manifest['authorized_keys_file'];
        $keyPolicy = file_get_contents($keyPath);
        if ($oldBatch === null || ! is_string($keyPolicy) || $keyPolicy === '') {
            throw new RuntimeException('Expected an admitted Batch identity and installed control key.');
        }
        $verification = app(SshVerificationState::class);
        $attempt = $verification->begin($target, $config, $credential);
        $save = static function (bool $enabled): SshManagedReverseGateway {
            $gateway = SshManagedReverseGateway::query()->findOrFail(1);
            $request = Request::create('/admin/settings/reverse-ssh', 'PUT', [
                'revision' => $gateway->revision,
                'enabled' => $enabled ? '1' : '0',
                'control_host' => $gateway->control_host,
                'control_port' => $gateway->control_port,
                'control_user' => $gateway->control_user,
                'control_host_key' => $gateway->control_host_key,
                'current_password' => 'StrongPassword!234',
            ]);
            $request->setUserResolver(static fn () => Auth::user());
            $request->setLaravelSession(app('session.store'));
            app()->instance('request', $request);
            app()->call([app(SshManagedReverseController::class), 'save'], ['request' => $request]);
            $current = $gateway->fresh();
            if ($current->enabled !== $enabled || $current->publication_pending) {
                throw new RuntimeException('Owner save did not reconcile actual control-key policy.');
            }

            return $current;
        };
        $deny = static function (callable $operation, string $reason): void {
            try {
                $operation();
                throw new RuntimeException('Stale or disabled authority unexpectedly admitted a remote operation.');
            } catch (SshTargetConnectionException $e) {
                if ($e->reason !== $reason) {
                    throw $e;
                }
            }
        };
        $commands = app(SshCommandRuntime::class);
        $files = app(SshFileRuntime::class);
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $owner);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($owner, $request);
        $core = app(TargetBatchCoordinator::class);
        $worker = app(TargetBatchWorker::class);
        $ids = [$target->target_id];
        $arguments = ['command' => 'printf managed-real-batch', 'timeout_seconds' => 10];
        $preview = static fn () => $core->preview($owner, $origin, 'ssh.command.run', $ids, $arguments);
        $create = static fn (array $approval) => $core->create(
            $owner, $origin, (string) Str::uuid(), 'ssh.command.run', $ids, $arguments, $approval['preview_token'],
        );
        $history = $create($preview());
        if (($worker->workOnce()['status'] ?? null) !== 'completed') {
            throw new RuntimeException('Initial real managed Reverse Batch failed.');
        }
        $historyRow = (array) DB::table('target_batch_items')->where('batch_id', $history['batch_id'])->sole();
        $preDisableBatch = $create($preview());
        $disabled = $save(false);
        if (file_get_contents($keyPath) !== '' || $target->fresh()->transport_revision !== $oldEpoch + 1) {
            throw new RuntimeException('Disable did not publish empty control policy and advance route epoch.');
        }
        $deny(fn () => $commands->run($owner, $target, 'true'), 'reverse_route_not_approved');
        $disabledTarget = $target->fresh();
        $disabledConfig = $config->fresh();
        $disabledAttempt = $verification->begin($disabledTarget, $disabledConfig, $credential);
        $disabledApproval = $preview();
        $disabledBatch = $create($disabledApproval);
        $disabledBinding = SshTargetBinding::hash($disabledTarget, $disabledConfig);
        $enabled = $save(true);
        $fresh = $target->fresh();
        $binding = SshTargetBinding::hash($fresh, $config);
        $newBatch = app(TargetBatchBinding::class)->hash($fresh);
        if ($enabled->revision !== $disabled->revision + 1
            || file_get_contents($keyPath) !== $keyPolicy
            || $fresh->transport_revision !== $oldEpoch + 2
            || $fresh->connection_state->value !== 'connected'
            || $fresh->last_tested_at !== null
            || $binding === $oldBinding || $newBatch === null || $newBatch === $oldBatch
            || ! hash_equals($oldCipher, (string) $credential->fresh()->encrypted_payload)) {
            throw new RuntimeException('Re-enable revived old authority or changed independent login identity.');
        }
        $noOp = $save(true);
        if ($noOp->revision !== $enabled->revision || $target->fresh()->transport_revision !== $oldEpoch + 2) {
            throw new RuntimeException('Identical reconciled save must not advance revisions.');
        }
        $deny(fn () => $verification->succeeded($target, $config, $credential, $attempt, '127.0.0.1'), 'target_changed');
        $verification->failed($disabledTarget, $disabledConfig, $credential, $disabledAttempt, 'tcp_unreachable');
        $deny(fn () => $verification->succeeded($disabledTarget, $disabledConfig, $credential, $disabledAttempt, '127.0.0.1'), 'target_changed');
        if ($target->fresh()->last_tested_at !== null || $binding === $disabledBinding) {
            throw new RuntimeException('Disabled-interval verification or binding survived real activation.');
        }
        try {
            $create($disabledApproval);
            throw new RuntimeException('Disabled-interval Preview authorized restored authority.');
        } catch (InvalidArgumentException $e) {
            if (! str_contains($e->getMessage(), 'Preview again')) {
                throw $e;
            }
        }
        for ($i = 0; $i < 2; $i++) {
            $outcome = $worker->workOnce();
            if (($outcome['status'] ?? null) !== 'blocked' || ($outcome['error_code'] ?? null) !== 'authorization_revoked') {
                throw new RuntimeException('Old real managed Batch crossed restored authority.');
            }
        }
        foreach ([$preDisableBatch, $disabledBatch] as $batch) {
            if ($core->status($owner, $origin, $batch['batch_id'])['items'][0]['status'] !== 'blocked') {
                throw new RuntimeException('Old managed Batch did not retain a blocked outcome.');
            }
        }
        $deny(fn () => $commands->run($owner, $target, 'true', expectedTargetBinding: $oldBinding), 'target_changed');
        $deny(fn () => $commands->run($owner, $target, 'true', expectedTargetBinding: $disabledBinding), 'target_changed');
        $path = '/home/deploy.prod/.mcp-reverse-aba-'.bin2hex(random_bytes(6));
        $deny(fn () => $files->write($owner, $target, $path, base64_encode('stale'), expectedTargetBinding: $oldBinding), 'target_changed');
        $status = app(SshJobMcpToolHandlers::class)->status(
            $owner, $target->target_id, hash('sha256', 'managed-reverse-e2e-job'), $job->id,
        );
        $retained = DB::table('ssh_command_jobs')->where('id', $job->id)->sole();
        if (($status['error']['code'] ?? null) !== 'target_not_found'
            || $retained->target_binding_hash !== $oldBinding || $retained->status !== 'completed') {
            throw new RuntimeException('Old Job was revived or its historical evidence was rewritten.');
        }
        app(SshTargetConnectionService::class)->test($fresh);
        $fresh = $target->fresh();
        $written = $files->write($owner, $fresh, $path, base64_encode('managed-fresh-authority'), expectedTargetBinding: $binding);
        if (($written['status'] ?? null) !== 'completed') {
            throw new RuntimeException('Fresh SFTP publication failed after re-enable.');
        }
        $result = $commands->run($owner, $fresh, 'cat -- '.escapeshellarg($path).' && rm -- '.escapeshellarg($path), expectedTargetBinding: $binding);
        if ($result['exit_code'] !== 0 || $result['stdout'] !== 'managed-fresh-authority') {
            throw new RuntimeException('Fresh pinned command did not observe the exact new SFTP bytes.');
        }
        $freshBatch = $create($preview());
        if (($worker->workOnce()['status'] ?? null) !== 'completed'
            || $core->status($owner, $origin, $freshBatch['batch_id'])['items'][0]['result']['result']['stdout'] !== 'managed-real-batch'
            || $historyRow !== (array) DB::table('target_batch_items')->where('batch_id', $history['batch_id'])->sole()
            || $worker->workOnce() !== null) {
            throw new RuntimeException('Fresh pinned managed Batch failed or historical evidence changed.');
        }
        echo "PASS: real Owner controller disable/re-enable, key publication, stale command/SFTP/Job/Batch/Verify fences and fresh pinned work; disabled-interval Preview, durable Worker, history.\n";
        exit(0);
    }

    if ($mode === 'verify') {
        if (is_file($root.'/verified-login-cipher-sha') && ! hash_equals(
            (string) file_get_contents($root.'/verified-login-cipher-sha'),
            hash('sha256', (string) $credential->encrypted_payload),
        )) {
            throw new RuntimeException('Transport-only installer changed the existing Gateway credential.');
        }
        $observed = app(SshTargetConnectionService::class)->test($target);
        if (! is_string($observed) || $target->fresh()->connection_state->value !== 'connected') {
            throw new RuntimeException('Real pinned Target SSH login was not recorded as connected.');
        }
        $output = $transport->withAuthenticatedSession(
            $config->endpoint(), $pin, $config->auth_method,
            $material['secret'], $material['passphrase'],
            static fn ($ssh): string => (string) $ssh->exec("printf 'managed-reverse-command-ok'"),
            $route,
        );
        if ($output !== 'managed-reverse-command-ok') {
            throw new RuntimeException('Real SSH command failed across managed reverse route.');
        }
        $content = $transport->withAuthenticatedSftpSession(
            $config->endpoint(), $pin, $config->auth_method,
            $material['secret'], $material['passphrase'],
            static function ($sftp): string {
                $path = '/home/deploy.prod/.mcp-reverse-e2e.txt';
                // phpseclib 4 SFTP::put() and delete() return void, not bool.
                // Verify the bytes actually stored and independently read back.
                $sftp->put($path, 'bounded-mcp-reverse-e2e', SFTP::SOURCE_STRING);
                $data = $sftp->get($path);
                if ($data !== 'bounded-mcp-reverse-e2e') {
                    throw new RuntimeException('Real SFTP file bytes differ from the uploaded payload.');
                }
                $sftp->delete($path);

                return $data;
            },
            // Exercise the actual bounded SFTP transport, not a potentially
            // unbounded debug call that can hang CI on a missing response.
            hrtime(true) + 30_000_000_000, $route,
        );
        if ($content !== 'bounded-mcp-reverse-e2e') {
            throw new RuntimeException('SFTP roundtrip failed across managed reverse route.');
        }
        // Wrong end-host pin must stop *before* login credentials are disclosed.
        $wrongKey = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(73), 32));
        try {
            $transport->authenticate(
                $config->endpoint(), SshHostKeyPin::fromLine($wrongKey),
                $config->auth_method, $material['secret'], $material['passphrase'], $route,
            );
            throw new RuntimeException('Mismatched Target SSHD pin unexpectedly authenticated.');
        } catch (SshTargetConnectionException $e) {
            if ($e->reason !== 'host_key_mismatch') {
                throw $e;
            }
        }
        echo "PASS: real Gateway PHP verify, end-host pin, command and SFTP through the installed Target systemd tunnel.\n";
        exit(0);
    }

    if ($mode === 'offline') {
        try {
            $transport->authenticate(
                $config->endpoint(), $pin, $config->auth_method,
                $material['secret'], $material['passphrase'], $route,
            );
            throw new RuntimeException('Disconnected tunnel silently provided a route.');
        } catch (SshTargetConnectionException $e) {
            if ($e->reason !== 'reverse_listener_unavailable') {
                throw $e;
            }
        }
        echo "PASS: stopped tunnel cannot fall back to the direct Target endpoint.\n";
        exit(0);
    }

    if ($mode === 'revoke') {
        app(SshManagedReverseEnrollmentService::class)->revoke(
            SshManagedReverseEnrollment::query()->where('target_id', $targetId)->sole(),
        );
        try {
            $policy->forTarget($target);
            throw new RuntimeException('Revoked route was still approved.');
        } catch (SshTargetConnectionException $e) {
            if ($e->reason !== 'reverse_route_not_approved') {
                throw $e;
            }
        }
        echo "PASS: revoked route blocks new Gateway operations.\n";
        exit(0);
    }
    throw new InvalidArgumentException('Unknown fixture mode.');
} catch (Throwable $exception) {
    // Laravel CLI exception renderer may otherwise exit 0 after printing an
    // unhandled exception. A green GitHub job must prove every assertion.
    // Only fixed-mode diagnostic context is disclosed, never the token/key.
    fwrite(STDERR, sprintf(
        "FAIL: managed Reverse SSH E2E mode=%s, exception=%s, message=%s\n",
        in_array($mode, ['enroll', 'reissue', 'readiness', 'readiness-stopped', 'verify', 'job', 'authority-aba', 'offline', 'revoke'], true) ? $mode : 'invalid',
        $exception::class,
        $exception->getMessage(),
    ));
    exit(1);
}
