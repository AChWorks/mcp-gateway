<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchCoordinator;
use App\Application\Batch\TargetBatchWorker;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Tests\TestCase;

/** Only a disposable, explicitly launched loopback sshd; no real Target use. */
final class TargetBatchOpenSshFixtureTest extends TestCase
{
    use RefreshDatabase;

    public function test_real_pinned_openssh_batch_executes_on_two_explicit_targets_with_durable_results(): void
    {
        if (getenv('V3_BATCH_SSH_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('Run only with disposable loopback sshd and isolated test keys.');
        }
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        });
        $hostPub = preg_split('/\s+/', trim((string) file_get_contents((string) getenv('V3_BATCH_SSH_HOST_KEY'))));
        $pin = implode(' ', array_slice($hostPub, 0, 2));
        $loginKey = (string) file_get_contents((string) getenv('V3_BATCH_SSH_LOGIN_KEY'));
        $user = User::query()->create([
            'name' => 'Isolated Batch SSH', 'email' => 'v3-batch-ssh-fixture@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $targets = [];
        for ($i = 0; $i < 2; $i++) {
            $target = app(SshTargetRegistration::class)->register(
                'batch-real-ssh-'.$i, 'Disposable OpenSSH '.$i, 'fixture.example.test',
                (int) getenv('V3_BATCH_SSH_PORT'), (string) getenv('V3_BATCH_SSH_USER'),
                $pin, 'private_key', $loginKey, null,
            );
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $targets[] = $target->target_id;
        }
        $core = app(TargetBatchCoordinator::class);
        $arguments = ['command' => "printf 'VerifiedSSHBatchOne'", 'timeout_seconds' => 10];
        $preview = $core->preview($user, $origin, 'ssh.command.run', $targets,
            $arguments, 'rolling', false, 1);
        self::assertSame(2, $preview['eligible_count']);
        $started = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run',
            $targets, $arguments, $preview['preview_token'], 'rolling', false, 1);
        self::assertSame('queued', $started['status']);
        $worker = app(TargetBatchWorker::class);
        foreach ($targets as $targetId) {
            $outcome = $worker->workOnce();
            self::assertSame($targetId, $outcome['target_id']);
            self::assertSame('completed', $outcome['status'], json_encode($outcome, JSON_THROW_ON_ERROR));
        }
        $state = $core->status($user, $origin, $started['batch_id']);
        self::assertSame('completed', $state['status']);
        self::assertSame(2, $state['counts']['completed']);
        foreach ($state['items'] as $item) {
            self::assertSame('VerifiedSSHBatchOne', $item['result']['result']['stdout']);
            self::assertSame(0, $item['result']['result']['exit_code']);
            self::assertSame('127.0.0.1', $item['result']['result']['connected_ip']);
            self::assertSame('utf-8', $item['result']['result']['stdout_encoding']);
        }
        self::assertNull($worker->workOnce());
    }
}
