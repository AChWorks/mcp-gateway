<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
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
                return [];
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
        $original = require database_path('migrations/2026_10_15_010000_create_ssh_command_jobs.php');

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
        $lifecycle->down();
        $original->down();
        self::assertFalse(Schema::hasTable('ssh_command_jobs'));
        // Restore test fixture schema inside this same isolated DB transaction.
        $original->up();
        $lifecycle->up();
        self::assertTrue(Schema::hasColumn(
            'ssh_command_jobs', 'admission_expires_at'));
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
