<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

final class SshJobLifecycleRecoveryTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // All network access denied: no real or simulated remote mutation.
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new SshTargetConnectionException('egress_denied');
            }
        });
    }

    public function test_crashed_preparing_recovers_and_late_probe_cannot_cross_launch_fence(): void
    {
        [$user, $target, $client] = $this->fixture();
        $requestId = (string) Str::uuid();
        $tools = app(SshJobMcpToolHandlers::class);
        $id = $tools->start($user, $target->target_id, $client, $requestId, 'echo one')['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'preparing', 'unit_mode' => null,
            'created_at' => now()->subMinutes(5),
            'preparing_expires_at' => now()->subMinute(),
            'admission_expires_at' => now()->addHour(),
        ]);
        self::assertSame('failed', $tools->status($user, $target->target_id, $client, $id)['result']['status']);
        self::assertSame('pre_dispatch_abandoned',
            DB::table('ssh_command_jobs')->where('id', $id)->value('terminal_reason'));
        self::assertSame($id, $tools->start($user, $target->target_id, $client,
            $requestId, 'echo one')['result']['job_id']);

        // A late PHP probe cannot proceed to mkdir/script/systemd-run.
        $transition = new \ReflectionMethod(SshJobCoordinator::class, 'transition');
        self::assertFalse($transition->invoke(app(SshJobCoordinator::class),
            $id, 'preparing', 'launch_unknown', ['unit_mode' => 'user']));
        self::assertSame('failed', DB::table('ssh_command_jobs')->where('id', $id)->value('status'));
        // Terminal pre-dispatch recovery requires no SSH/Target permissions to prune.
        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subDay()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
    }

    public function test_preparing_grace_snapshot_is_not_shortened_by_later_owner_policy(): void
    {
        [$user, $target, $client] = $this->fixture();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_preparing_grace_seconds' => 120,
        ]);
        $tool = app(SshJobMcpToolHandlers::class);
        $id = $tool->start($user, $target->target_id, $client,
            (string) Str::uuid(), 'echo snapshot')['result']['job_id'];
        $created = Carbon::now();
        DB::table('ssh_command_jobs')->where('id', $id)
            ->update(['status' => 'preparing']);

        try {
            // A new Owner value may not preempt an already-probing request.
            DB::table('operational_settings')->where('id', 1)->update([
                'ssh_job_preparing_grace_seconds' => 30,
            ]);
            Carbon::setTestNow($created->copy()->addSeconds(45));
            self::assertSame('preparing',
                $tool->status($user, $target->target_id, $client, $id)['result']['status']);
            Carbon::setTestNow($created->copy()->addSeconds(121));
            self::assertSame('failed',
                $tool->status($user, $target->target_id, $client, $id)['result']['status']);
            self::assertSame('pre_dispatch_abandoned',
                DB::table('ssh_command_jobs')->where('id', $id)->value('terminal_reason'));
        } finally {
            Carbon::setTestNow();
        }
    }

    public function test_expired_uncertain_leases_free_admission_without_erase_or_replay(): void
    {
        [$user, $target, $client] = $this->fixture();
        $tools = app(SshJobMcpToolHandlers::class);
        $old = [];
        foreach (['launch_unknown', 'cancel_requested'] as $state) {
            $requestId = (string) Str::uuid();
            $id = $tools->start($user, $target->target_id, $client,
                $requestId, 'echo keep')['result']['job_id'];
            DB::table('ssh_command_jobs')->where('id', $id)->update([
                'status' => $state, 'unit_mode' => 'user',
                'admission_expires_at' => now()->subMinute(),
                'expires_at' => now()->subDay(),
            ]);
            $old[] = [$id, $requestId, $state];
        }
        // A remote script MIGHT have run; expiry is NOT proof of completion,
        // nor permission to re-execute that same caller-generated request ID.
        $third = $tools->start($user, $target->target_id, $client, (string) Str::uuid(), 'echo new');
        self::assertSame('unsupported', $third['result']['status']);
        self::assertSame(3, DB::table('ssh_command_jobs')->count());
        foreach ($old as [$id, $requestId, $state]) {
            self::assertSame($id, $tools->start($user, $target->target_id, $client,
                $requestId, 'echo keep')['result']['job_id']);
            self::assertSame($state, DB::table('ssh_command_jobs')->where('id', $id)->value('status'));
        }
        // Pruning cannot delete unverified remote evidence even past retention.
        self::assertSame(0, app(SshJobCoordinator::class)->prune());
        self::assertSame(3, DB::table('ssh_command_jobs')->count());
    }

    public function test_owner_tunable_active_count_and_maximum_runtime_apply_to_new_jobs(): void
    {
        [$user, $target, $client] = $this->fixture();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_max_active_per_user' => 3,
            'ssh_job_max_runtime_seconds' => 86400,
            'ssh_job_retention_hours' => 168,
            'ssh_job_preparing_grace_seconds' => 240,
            'ssh_job_reconcile_grace_seconds' => 900,
        ]);
        $tools = app(SshJobMcpToolHandlers::class);
        foreach (range(1, 3) as $i) {
            $id = $tools->start($user, $target->target_id, $client,
                (string) Str::uuid(), 'echo hello-'.$i, 86400)['result']['job_id'];
            DB::table('ssh_command_jobs')->where('id', $id)->update(['status' => 'running']);
            $row = DB::table('ssh_command_jobs')->where('id', $id)->first();
            self::assertSame(86400, (int) $row->runtime_seconds);
            self::assertSame(900, (int) $row->reconcile_grace_seconds);
            self::assertSame(
                now()->addSeconds(240)->timestamp,
                Carbon::parse($row->preparing_expires_at)->timestamp,
            );
            self::assertGreaterThan(now()->addDay()->timestamp,
                Carbon::parse($row->admission_expires_at)->timestamp);
        }
        self::assertSame('rate_limited',
            $tools->start($user, $target->target_id, $client, (string) Str::uuid(),
                'echo four', 86400)['error']['code']);

        DB::table('ssh_command_jobs')->update(['admission_expires_at' => now()->subMinute()]);
        self::assertSame('invalid_input',
            $tools->start($user, $target->target_id, $client, (string) Str::uuid(),
                'echo five', 86401)['error']['code']);
        $fresh = $tools->start($user, $target->target_id, $client, (string) Str::uuid(),
            'echo six', 86400);
        self::assertSame('unsupported', $fresh['result']['status']);
        self::assertSame(4, DB::table('ssh_command_jobs')->count());
    }

    public function test_minimum_grace_delayed_launch_keeps_single_slot_through_actual_dispatch_and_runtime(): void
    {
        [$user, $target, $client] = $this->fixture();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_job_max_active_per_user' => 1,
            'ssh_job_preparing_grace_seconds' => 30,
            'ssh_job_reconcile_grace_seconds' => 60,
        ]);
        $tool = app(SshJobMcpToolHandlers::class);
        $requestId = (string) Str::uuid();
        $id = $tool->start($user, $target->target_id, $client,
            $requestId, 'echo never-relaunch', 16)['result']['job_id'];
        // Real SSH is denied. Re-create just the durable prelaunch state to
        // test the scheduling fence with deterministic elapsed wall time.
        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'preparing', 'unit_mode' => null,
        ]);
        $first = DB::table('ssh_command_jobs')->where('id', $id)->first();
        $originalExpiry = Carbon::parse($first->admission_expires_at);
        self::assertSame(60, (int) $first->reconcile_grace_seconds);
        $start = Carbon::now();
        $transition = new \ReflectionMethod(SshJobCoordinator::class, 'transition');
        $renew = new \ReflectionMethod(SshJobCoordinator::class, 'reserveDispatchLease');

        try {
            Carbon::setTestNow($start->copy()->addSeconds(29));
            self::assertTrue($transition->invoke(app(SshJobCoordinator::class),
                $id, 'preparing', 'launch_unknown', ['unit_mode' => 'user']));
            $fenced = DB::table('ssh_command_jobs')->where('id', $id)->first();
            self::assertGreaterThan(
                Carbon::now()->addSeconds(360 + 90 + 16 + 60 - 1)->timestamp,
                Carbon::parse($fenced->admission_expires_at)->timestamp,
            );
            // The original creation-based lease expires while post-fence
            // staging still runs. Admission must remain consumed.
            Carbon::setTestNow($start->copy()->addSeconds(160));
            self::assertTrue($originalExpiry->isPast());
            self::assertSame('rate_limited',
                $tool->start($user, $target->target_id, $client,
                    (string) Str::uuid(), 'echo overlap', 16)['error']['code']);

            // Simulate a slow but still-fenced pipeline just before dispatch.
            // This forces a real deadline *extension*, not only a fixed
            // creation-time budget.
            Carbon::setTestNow($start->copy()->addSeconds(449));
            $beforeDispatch = DB::table('ssh_command_jobs')
                ->where('id', $id)->value('admission_expires_at');
            self::assertTrue($renew->invoke(app(SshJobCoordinator::class), $id));
            $afterDispatch = DB::table('ssh_command_jobs')
                ->where('id', $id)->value('admission_expires_at');
            self::assertGreaterThan(
                Carbon::parse((string) $beforeDispatch)->timestamp,
                Carbon::parse((string) $afterDispatch)->timestamp,
            );

            // Later Owner policy changes cannot affect this Job's original
            // one-minute reconciliation grace. No zero or shorter lease.
            DB::table('operational_settings')->where('id', 1)->update([
                'ssh_job_reconcile_grace_seconds' => 3600,
            ]);
            self::assertSame(60,
                (int) DB::table('ssh_command_jobs')
                    ->where('id', $id)->value('reconcile_grace_seconds'));
            self::assertEqualsWithDelta(
                90 + 16 + 60,
                Carbon::now()->diffInSeconds(Carbon::parse($afterDispatch)),
                1,
            );
            Carbon::setTestNow(Carbon::parse($afterDispatch)->subSecond());
            self::assertSame('rate_limited',
                $tool->start($user, $target->target_id, $client,
                    (string) Str::uuid(), 'echo still-overlap', 16)['error']['code']);

            Carbon::setTestNow(Carbon::parse($afterDispatch)->addSecond());
            self::assertSame('unsupported',
                $tool->start($user, $target->target_id, $client,
                    (string) Str::uuid(), 'echo new', 16)['result']['status']);
            // Old immutable request ID continues to resolve to the one old
            // journal entry; no command has ever been remotely dispatched.
            self::assertSame($id, $tool->start($user, $target->target_id, $client,
                $requestId, 'echo never-relaunch', 16)['result']['job_id']);
            self::assertSame('launch_unknown',
                DB::table('ssh_command_jobs')->where('id', $id)->value('status'));
        } finally {
            Carbon::setTestNow();
        }
    }

    public function test_dispatch_lease_never_shortens_and_stale_or_canceled_launch_cannot_dispatch(): void
    {
        [$user, $target, $client] = $this->fixture();
        $tool = app(SshJobMcpToolHandlers::class);
        $id = $tool->start($user, $target->target_id, $client,
            (string) Str::uuid(), 'echo no-replay', 16)['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'launch_unknown', 'unit_mode' => 'user',
            'admission_expires_at' => now()->addDays(2),
        ]);
        $renew = new \ReflectionMethod(SshJobCoordinator::class, 'reserveDispatchLease');
        $far = DB::table('ssh_command_jobs')->where('id', $id)->value('admission_expires_at');
        self::assertTrue($renew->invoke(app(SshJobCoordinator::class), $id));
        self::assertSame($far,
            DB::table('ssh_command_jobs')->where('id', $id)->value('admission_expires_at'));

        DB::table('ssh_command_jobs')->where('id', $id)
            ->update(['status' => 'cancel_requested']);
        self::assertFalse($renew->invoke(app(SshJobCoordinator::class), $id));
        DB::table('ssh_command_jobs')->where('id', $id)
            ->update(['status' => 'launch_unknown',
                'admission_expires_at' => now()->subSecond()]);
        self::assertFalse($renew->invoke(app(SshJobCoordinator::class), $id));

        // A still-live lease must not permit dispatch after the original
        // Gateway principal has been disabled, regardless of old snapshots.
        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'admission_expires_at' => now()->addHour(),
        ]);
        DB::table('users')->where('id', $user->getKey())->update(['access_enabled' => false]);
        self::assertFalse($renew->invoke(app(SshJobCoordinator::class), $id));
    }

    public function test_operator_refuses_active_lease_and_requires_exact_attested_original_binding(): void
    {
        [$user, $target, $client] = $this->fixture();
        $jobId = app(SshJobMcpToolHandlers::class)->start($user, $target->target_id,
            $client, (string) Str::uuid(), 'echo secure')['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $jobId)->update(['status' => 'launch_unknown']);
        $original = DB::table('ssh_command_jobs')->where('id', $jobId)->first();
        self::assertSame((int) $user->getKey(), (int) $original->original_user_id);
        self::assertSame((string) $target->getKey(), $original->original_target_record_id);
        self::assertSame('ssh-lifecycle-test', $original->original_target_id);
        self::assertSame('fixture.example.test', $original->original_host);
        self::assertSame(22, (int) $original->original_port);
        self::assertSame('fixture-user', $original->original_os_username);
        self::assertSame('password', $original->original_auth_method);
        self::assertSame(64, strlen((string) $original->original_host_key_digest));
        $jobs = app(SshJobCoordinator::class);
        try {
            $jobs->operatorRetire($jobId, $original->target_binding_hash,
                'Original systemd unit stopped and spool removed');
            self::fail('Admission must remain protected until the lease ends');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('job_admission_active', $exception->reason);
        }
        self::assertSame(1, Artisan::call('gateway:ssh-jobs-reconcile', [
            'operation' => 'retire', 'job' => $jobId,
            '--confirm' => $jobId, '--binding' => $original->target_binding_hash,
            '--reason' => 'Original systemd unit stopped and spool removed',
        ]));

        DB::table('ssh_command_jobs')->where('id', $jobId)->update([
            'admission_expires_at' => now()->subMinute(),
        ]);
        try {
            $jobs->operatorRetire($jobId, str_repeat('a', 64),
                'Original systemd unit stopped and spool removed');
            self::fail('A mismatching immutable Target binding must never retire another Job');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_not_found', $exception->reason);
        }

        // Simulate user and Target deletion/rotation. Operator records local
        // attestation WITHOUT using live permissions or a rebound host.
        $user->delete();
        $target->delete();
        self::assertSame(0, Artisan::call('gateway:ssh-jobs-reconcile', [
            'operation' => 'inspect', 'job' => $jobId,
        ]));
        $inspection = Artisan::output();
        self::assertStringContainsString('fixture.example.test:22', $inspection);
        self::assertStringContainsString('fixture-user', $inspection);
        self::assertStringContainsString((string) $original->target_binding_hash, $inspection);
        self::assertStringNotContainsString('test-secret', $inspection);
        self::assertSame(0, Artisan::call('gateway:ssh-jobs-reconcile', [
            'operation' => 'retire', 'job' => $jobId,
            '--confirm' => $jobId, '--binding' => $original->target_binding_hash,
            '--reason' => 'Verified original remote unit inactive and old private spool deleted',
            '--attest-remote-cleaned' => true,
        ]));
        $result = $jobs->operatorRetire($jobId, $original->target_binding_hash,
            'Verified original remote unit inactive and old private spool deleted');
        self::assertSame('retired', $result['status']);
        self::assertFalse($result['complete']);
        self::assertFalse($result['continuation_available']);
        $row = DB::table('ssh_command_jobs')->where('id', $jobId)->first();
        self::assertNull($row->user_id);
        self::assertNull($row->target_record_id);
        // Non-FK immutable identity survives linked User/Target deletion.
        self::assertSame($original->original_user_id, $row->original_user_id);
        self::assertSame($original->original_target_record_id, $row->original_target_record_id);
        self::assertSame($original->original_host, $row->original_host);
        self::assertSame($original->original_host_key_digest, $row->original_host_key_digest);
        self::assertSame($original->script_digest, $row->script_digest);
        self::assertSame($original->request_id, $row->request_id);
        self::assertSame('operator_attested_cleanup', $row->terminal_reason);
        self::assertNotNull($row->operator_attested_at);
        self::assertSame(0, app(SshJobCoordinator::class)->prune());
        DB::table('ssh_command_jobs')->where('id', $jobId)->update(['expires_at' => now()->subDay()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
    }

    public function test_revoked_access_or_rebound_target_prevents_automatic_remote_cleanup(): void
    {
        [$user, $target, $client] = $this->fixture();
        $jobId = app(SshJobMcpToolHandlers::class)->start($user, $target->target_id,
            $client, (string) Str::uuid(), 'echo old')['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $jobId)->update([
            'status' => 'completed', 'expires_at' => now()->subDay(),
        ]);
        DB::table('ssh_direct_target_configs')->where('target_record_id', $target->getKey())
            ->update(['username' => 'rotated-identity']);
        self::assertSame(0, app(SshJobCoordinator::class)->prune());
        DB::table('ssh_direct_target_configs')->where('target_record_id', $target->getKey())
            ->update(['username' => 'fixture-user']);
        $user->forceFill(['access_enabled' => false])->save();
        self::assertSame(0, app(SshJobCoordinator::class)->prune());
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
    }

    public function test_guarded_schema_rollback_succeeds_only_after_safe_operator_retirement_and_pruning(): void
    {
        [$user, $target, $client] = $this->fixture();
        $id = app(SshJobMcpToolHandlers::class)->start(
            $user, $target->target_id, $client, (string) Str::uuid(), 'echo maybe')['result']['job_id'];
        $job = DB::table('ssh_command_jobs')->where('id', $id)->first();
        $lifecycle = require database_path('migrations/2026_10_15_020000_add_ssh_job_lifecycle_policy.php');
        $snapshot = require database_path('migrations/2026_10_15_030000_snapshot_ssh_job_admission_policy.php');
        $original = require database_path('migrations/2026_10_15_010000_create_ssh_command_jobs.php');

        try {
            $snapshot->down();
            self::fail('Rollback must keep immutable Owner policy with unresolved Journal rows');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('Reconcile and prune', $exception->getMessage());
        }

        try {
            $lifecycle->down();
            self::fail('Rollback must not erase an unresolved no-replay identity');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('Reconcile and prune', $exception->getMessage());
        }

        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'launch_unknown', 'admission_expires_at' => now()->subDay(),
        ]);
        app(SshJobCoordinator::class)->operatorRetire(
            $id, $job->target_binding_hash,
            'Original remote unit and private spool verified already removed',
        );
        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subDay()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());

        // Exercise real down/up migration operations, not a mocked guard.
        $snapshot->down();
        $lifecycle->down();
        $original->down();
        self::assertFalse(Schema::hasTable('ssh_command_jobs'));
        // Restore test fixture schema inside this same isolated DB transaction.
        $original->up();
        $lifecycle->up();
        $snapshot->up();
        self::assertTrue(Schema::hasColumn(
            'ssh_command_jobs', 'admission_expires_at'));
        self::assertTrue(Schema::hasColumn(
            'ssh_command_jobs', 'preparing_expires_at'));
    }

    public function test_rebound_target_cannot_receive_later_job_phase_commands_or_sftp(): void
    {
        [$user, $target, $client] = $this->fixture();
        $config = SshTargetConfig::query()
            ->where('target_record_id', $target->getKey())->firstOrFail();
        $original = SshTargetBinding::hash($target, $config);

        // A Job is admitted against original A. The real initial probe is
        // blocked by the test's no-egress policy; simulate its successful
        // immutable pre-dispatch fence without any remote systemd activity.
        $tool = app(SshJobMcpToolHandlers::class);
        $id = $tool->start($user, $target->target_id, $client,
            (string) Str::uuid(), 'echo original-host')['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'preparing', 'unit_mode' => null,
            'preparing_expires_at' => now()->addMinute(),
            'admission_expires_at' => now()->addHour(),
        ]);
        $transition = new \ReflectionMethod(SshJobCoordinator::class, 'transition');
        self::assertTrue($transition->invoke(app(SshJobCoordinator::class),
            $id, 'preparing', 'launch_unknown', ['unit_mode' => 'user']));

        // Represents a completed admin reconfiguration+reconnect of the SAME
        // Target ID from endpoint A to B between distinct SSH connections.
        DB::table('ssh_direct_target_configs')->where('id', $config->getKey())->update([
            'host' => 'replacement-host.example.test',
            'username' => 'replacement-user',
        ]);
        self::assertSame(TargetConnectionState::Connected,
            $target->fresh()->getAttribute('connection_state'));
        $changed = SshTargetConfig::query()
            ->whereKey($config->getKey())->firstOrFail();
        self::assertNotSame($original,
            SshTargetBinding::hash($target, $changed));

        $spy = new class implements SshDialAddressPolicy
        {
            public int $attempts = 0;

            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                $this->attempts++;

                throw new SshTargetConnectionException('egress_denied');
            }
        };
        $this->app->instance(SshDialAddressPolicy::class, $spy);
        $command = app(SshCommandRuntime::class);
        $files = app(SshFileRuntime::class);
        $directory = '/var/tmp/.mcp-gateway-job-'.$id;
        $denied = static function (callable $operation): void {
            try {
                $operation();
                self::fail('A Job phase must not dial or mutate the rebound host.');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('target_changed', $exception->reason);
            }
        };

        // These are distinct actual runtime entrypoints (not an initial
        // Coordinator-only check). Every one must reject B before dialing.
        foreach ([
            'post-fence-mkdir' => 'mkdir -m 700 -- '.escapeshellarg($directory),
            'final-systemd-run' => 'systemd-run --unit=test -- /bin/sh /tmp/script.sh',
            'late-probe' => 'command -v systemd-run',
        ] as $phase => $text) {
            $denied(static fn () => $command->run($user, $target, $text, 8, $original));
        }
        $denied(static fn () => $files->write(
            $user, $target, $directory.'/script.sh', base64_encode('echo original'),
            expectedTargetBinding: $original,
        ));
        $denied(static fn () => $files->write(
            $user, $target, $directory.'/wrapper.sh', base64_encode('#!/bin/sh'),
            expectedTargetBinding: $original,
        ));
        $denied(static fn () => $files->read(
            $user, $target, $directory.'/exit-code', 0, 8,
            expectedTargetBinding: $original,
        ));
        self::assertSame(0, $spy->attempts, 'The rebound host must not receive any network dial.');
        self::assertSame($original,
            DB::table('ssh_command_jobs')->where('id', $id)->value('target_binding_hash'));
        self::assertSame('launch_unknown',
            DB::table('ssh_command_jobs')->where('id', $id)->value('status'));
        self::assertSame('target_not_found',
            $tool->status($user, $target->target_id, $client, $id)['error']['code']);
    }

    /** @return array{0:User,1:Target,2:string} */
    private function fixture(): array
    {
        $owner = User::query()->create([
            'name' => 'SSH lifecycle fixture',
            'email' => bin2hex(random_bytes(6)).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $key = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32));
        $target = app(SshTargetRegistration::class)->register(
            'ssh-lifecycle-test', 'SSH lifecycle test', 'fixture.example.test', 22,
            'fixture-user', $key, 'password', 'test-secret', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return [$owner, $target, hash('sha256', 'lifecycle-client')];
    }
}
