<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use phpseclib4\Exception\FileSystemException;
use Tests\TestCase;

final class SshJobMcpTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // Deterministic deny-only synthetic network policy: no real outbound
        // SSH traffic during these authorization/idempotency unit fixtures.
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return [];
            }
        });
    }

    public function test_unsupported_host_fails_closed_and_exact_start_intent_is_durable_once(): void
    {
        $user = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'chatgpt-test-client');
        $requestId = (string) Str::uuid();
        $tool = app(SshJobMcpToolHandlers::class);

        $first = $tool->start($user, $target->target_id, $client, $requestId, 'echo safe', 30);
        self::assertFalse($first['ok']);
        self::assertSame('job_unsupported', $first['error']['code']);
        self::assertStringContainsString('could not be verified', $first['error']['message']);
        self::assertStringNotContainsString('lacks a supported', $first['error']['message']);
        $failure = DB::table('activity_events')->where('operation', 'ssh-job-start')
            ->where('error_code', 'job_unsupported')->first();
        self::assertNotNull($failure);
        $details = app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($user, (string) $failure->correlation_id);
        self::assertTrue($details['ok']);
        self::assertSame('unknown', $details['events'][0]['diagnostics']['provider_cause']);
        self::assertSame('connection_setup', $details['events'][0]['diagnostics']['failure_stage']);
        $id = $first['result']['job_id'];
        self::assertSame('unsupported', $first['result']['status']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
        self::assertArrayNotHasKey('script', (array) DB::table('ssh_command_jobs')->sole());
        self::assertStringNotContainsString('echo safe', json_encode(DB::table('ssh_command_jobs')->sole()));

        // The same request key does NOT re-probe/re-launch, even within the
        // same second; a changed script or runtime is a conflict.
        $duplicate = $tool->start($user, $target->target_id, $client, $requestId, 'echo safe', 30);
        self::assertSame($id, $duplicate['result']['job_id']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
        self::assertSame('invalid_input',
            $tool->start($user, $target->target_id, $client, $requestId, 'echo changed', 30)['error']['code']);
        self::assertSame('invalid_input',
            $tool->start($user, $target->target_id, $client, $requestId, 'echo safe', 31)['error']['code']);

        $status = $tool->status($user, $target->target_id, $client, $id);
        self::assertSame('unsupported', $status['result']['status']);
        self::assertFalse($status['result']['retry_safe']);
    }

    public function test_scoped_read_only_job_listing_filters_paginates_and_rejects_tampered_cursors(): void
    {
        $owner = $this->user('owner');
        $other = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'client-list');
        $otherClient = hash('sha256', 'client-list-other');
        $tool = app(SshJobMcpToolHandlers::class);
        self::assertSame([], $tool->list($owner, $target->target_id, $client)['result']['jobs']);
        $ids = [];
        for ($i = 0; $i < 5; $i++) {
            $ids[] = $tool->start(
                $owner, $target->target_id, $client, (string) Str::uuid(), 'echo safe-'.$i,
            )['result']['job_id'];
        }
        $foreign = $tool->start(
            $other, $target->target_id, $client, (string) Str::uuid(), 'echo private',
        )['result']['job_id'];
        $foreignClient = $tool->start(
            $owner, $target->target_id, $otherClient, (string) Str::uuid(), 'echo private-client',
        )['result']['job_id'];

        // Nonterminal uncertain Jobs survive nominal expiration; expired
        // terminal evidence is excluded even before operator-side pruning.
        DB::table('ssh_command_jobs')->where('id', $ids[1])
            ->update(['status' => 'launch_unknown', 'expires_at' => now()->subHour()]);
        DB::table('ssh_command_jobs')->where('id', $ids[0])
            ->update(['status' => 'completed', 'exit_code' => 0,
                'terminal_reason' => 'script_exit', 'expires_at' => now()->subHour()]);

        $page1 = $tool->list($owner, $target->target_id, $client, limit: 2);
        self::assertTrue($page1['ok']);
        self::assertCount(2, $page1['result']['jobs']);
        self::assertTrue($page1['result']['has_more']);
        $cursor = $page1['result']['next_cursor'];
        self::assertSame(91, strlen($cursor));
        // A concurrent insert after the first page must not be duplicated or
        // unexpectedly move onto an earlier keyset page.
        $newId = $tool->start(
            $owner, $target->target_id, $client, (string) Str::uuid(), 'echo inserted-later',
        )['result']['job_id'];
        self::assertSame($newId, $tool->list(
            $owner, $target->target_id, $client, limit: 1,
        )['result']['jobs'][0]['job_id']);
        $page2 = $tool->list($owner, $target->target_id, $client, cursor: $cursor, limit: 2);
        self::assertTrue($page2['ok']);
        self::assertFalse($page2['result']['has_more']);
        $all = array_merge($page1['result']['jobs'], $page2['result']['jobs']);
        self::assertSame(array_reverse(array_slice($ids, 1)), array_column($all, 'job_id'));
        self::assertSame('launch_unknown', end($all)['status']);
        self::assertSame(0, DB::table('activity_events')->where('operation', 'ssh-jobs-list')->count());
        self::assertArrayNotHasKey('script_digest', $all[0]);
        self::assertArrayNotHasKey('client_identity_hash', $all[0]);
        self::assertArrayNotHasKey('original_host', $all[0]);
        self::assertSame([], $tool->list($other, $target->target_id, $otherClient)['result']['jobs']);
        self::assertSame([], $tool->list($owner, $target->target_id, hash('sha256', 'new-chat-client'))['result']['jobs']);
        self::assertSame('invalid_input', $tool->list(
            $owner, $target->target_id, $client, cursor: substr($cursor, 0, -1).(str_ends_with($cursor, 'a') ? 'b' : 'a'),
        )['error']['code']);
        self::assertSame('invalid_input', $tool->list(
            $owner, $target->target_id, $client, status: 'running', cursor: $cursor,
        )['error']['code']);
        self::assertSame('invalid_input', $tool->list(
            $owner, $target->target_id, $client, status: 'whatever',
        )['error']['code']);
        self::assertSame('invalid_input', $tool->list(
            $owner, $target->target_id, $client, limit: 51,
        )['error']['code']);
        self::assertSame([], $tool->list($owner, $target->target_id, $client, status: 'running')['result']['jobs']);

        // Both foreign records remain in DB, but no tool result exposes them.
        self::assertSame(8, DB::table('ssh_command_jobs')->count());
        self::assertNotContains($newId, array_column($all, 'job_id'));
        self::assertNotContains($foreign, array_column($all, 'job_id'));
        self::assertNotContains($foreignClient, array_column($all, 'job_id'));

        $target->forceFill(['operations_paused' => true])->save();
        self::assertSame('target_paused', $tool->list($owner, $target->target_id, $client)['error']['code']);
        $owner->forceFill(['access_enabled' => false])->save();
        self::assertSame('target_not_found', $tool->list($owner, $target->target_id, $client)['error']['code']);
        $owner->forceFill(['access_enabled' => true])->save();
        $target->forceFill(['operations_paused' => false])->save();
        DB::table('ssh_direct_target_configs')->where('target_record_id', $target->getKey())
            ->update(['username' => 'rotated-list-account']);
        self::assertSame([], $tool->list($owner, $target->target_id, $client)['result']['jobs']);
    }

    public function test_job_authorization_remains_bound_to_user_client_target_and_config(): void
    {
        $user = $this->user('owner');
        $other = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'client-a');
        $id = app(SshJobMcpToolHandlers::class)->start(
            $user, $target->target_id, $client, (string) Str::uuid(), 'echo confidential',
        )['result']['job_id'];
        $tool = app(SshJobMcpToolHandlers::class);

        self::assertSame('target_not_found',
            $tool->status($other, $target->target_id, $client, $id)['error']['code']);
        self::assertSame('target_not_found',
            $tool->status($user, $target->target_id, hash('sha256', 'other-client'), $id)['error']['code']);
        self::assertSame('target_not_found',
            $tool->output($other, $target->target_id, $client, $id)['error']['code']);
        self::assertSame('target_not_found',
            $tool->cancel($other, $target->target_id, $client, $id)['error']['code']);

        DB::table('ssh_direct_target_configs')->where('target_record_id', $target->getKey())
            ->update(['username' => 'rotated-account']);
        self::assertSame('target_not_found',
            $tool->status($user, $target->target_id, $client, $id)['error']['code']);
    }

    public function test_paused_target_verifies_job_handle_before_emitting_diagnostic_activity(): void
    {
        $owner = $this->user('owner');
        $foreign = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'paused-authenticated-client');
        $otherClient = hash('sha256', 'other-paused-client');
        $jobs = app(SshJobMcpToolHandlers::class);

        $ownedId = $jobs->start(
            $owner, $target->target_id, $client, (string) Str::uuid(), 'echo owned',
        )['result']['job_id'];
        $foreignId = $jobs->start(
            $foreign, $target->target_id, $otherClient, (string) Str::uuid(), 'echo foreign',
        )['result']['job_id'];
        $otherClientId = $jobs->start(
            $owner, $target->target_id, $otherClient, (string) Str::uuid(), 'echo other-client',
        )['result']['job_id'];
        $target->forceFill(['operations_paused' => true])->save();

        $before = DB::table('activity_events')->count();
        Log::spy();
        $unknown = (string) Str::ulid();
        foreach (['status', 'output', 'cancel'] as $method) {
            foreach ([
                [$owner, $client, 'not-a-ulid'],
                [$owner, $client, $unknown],
                [$owner, $client, $foreignId],
                [$owner, $client, $otherClientId],
                [$owner, $otherClient, $ownedId],
                [$foreign, $client, $ownedId],
            ] as [$actor, $identity, $handle]) {
                $result = $jobs->{$method}($actor, $target->target_id, $identity, $handle);
                self::assertFalse($result['ok']);
                self::assertSame('target_not_found', $result['error']['code']);
                self::assertArrayNotHasKey('diagnostic_reference', $result['error']);
            }
        }
        self::assertSame($before, DB::table('activity_events')->count(),
            'Pausing must not make invented or foreign Job handles auditable.');
        Log::shouldNotHaveReceived('warning');

        foreach (['status', 'output', 'cancel'] as $method) {
            $result = $jobs->{$method}($owner, $target->target_id, $client, $ownedId);
            self::assertSame('target_paused', $result['error']['code']);
            $reference = $result['error']['diagnostic_reference'] ?? null;
            self::assertIsString($reference);
            $evidence = app(OperationDiagnosticsMcpToolHandlers::class)->read($owner, $reference);
            self::assertTrue($evidence['ok']);
            self::assertSame('target_paused', $evidence['events'][0]['error_code']);
        }
        self::assertSame($before + 3, DB::table('activity_events')->count());
        self::assertSame(3, DB::table('ssh_command_jobs')->count());

        // Removing current rights or actor access must not disclose pause
        // status, Job existence, or emit any diagnostic for this handle.
        // Owners intentionally bypass individual permission denials;
        // disabling the entire principal actually revokes an Owner.
        $owner->forceFill(['access_enabled' => false])->save();
        $revoked = $jobs->status($owner, $target->target_id, $client, $ownedId);
        self::assertSame('target_not_found', $revoked['error']['code']);
        self::assertArrayNotHasKey('diagnostic_reference', $revoked['error']);
        self::assertSame($before + 3, DB::table('activity_events')->count());
    }

    public function test_paused_job_cannot_reveal_target_status_after_selected_operator_permission_is_denied(): void
    {
        $operator = $this->user('operator');
        $operator->forceFill(['target_scope_mode' => 'selected'])->save();
        $target = $this->target();
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $client = hash('sha256', 'operator-paused-job-client');
        $handler = app(SshJobMcpToolHandlers::class);
        $created = $handler->start(
            $operator, $target->target_id, $client, (string) Str::uuid(), 'echo owned operator job',
        );
        self::assertSame('unsupported', $created['result']['status']);
        $jobId = $created['result']['job_id'];
        $target->forceFill(['operations_paused' => true])->save();

        $first = $handler->status($operator, $target->target_id, $client, $jobId);
        self::assertSame('target_paused', $first['error']['code']);
        $before = DB::table('activity_events')->count();

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        Log::spy();
        foreach (['status', 'output', 'cancel'] as $operation) {
            $denied = $handler->{$operation}($operator, $target->target_id, $client, $jobId);
            self::assertSame('target_not_found', $denied['error']['code']);
            self::assertArrayNotHasKey('diagnostic_reference', $denied['error']);
        }
        self::assertSame($before, DB::table('activity_events')->count());
        Log::shouldNotHaveReceived('warning');
    }

    public function test_only_native_missing_output_status_is_treated_as_not_yet_available(): void
    {
        $method = new \ReflectionMethod(SshJobCoordinator::class, 'isMissingJobOutput');
        $jobs = app(SshJobCoordinator::class);
        foreach ([2, 10] as $missingCode) {
            $missing = new SshTargetConnectionException('file_unavailable', [
                'exception_class' => FileSystemException::class,
                'source_error_code' => $missingCode,
                'source_error_message' => 'No such path',
            ]);
            self::assertTrue($method->invoke($jobs, $missing));
        }
        foreach ([3, 4, 5, 0, 11] as $failureCode) {
            $failure = new SshTargetConnectionException('file_unavailable', [
                'exception_class' => FileSystemException::class,
                'source_error_code' => $failureCode,
                'source_error_message' => 'Observed native SFTP error',
            ]);
            self::assertFalse($method->invoke($jobs, $failure));
        }
        foreach ([
            new SshTargetConnectionException('file_unavailable'),
            new SshTargetConnectionException('file_unavailable', [
                'provider_cause_unknown' => true,
            ]),
            new SshTargetConnectionException('file_unavailable', [
                'exception_class' => \RuntimeException::class, 'source_error_code' => 2,
            ]),
            new SshTargetConnectionException('connection_busy', [
                'exception_class' => FileSystemException::class,
                'source_error_code' => 2,
            ]),
        ] as $unproven) {
            self::assertFalse($method->invoke($jobs, $unproven));
        }
    }

    public function test_capture_truncation_never_claims_completeness_without_reader_proof(): void
    {
        $method = new \ReflectionMethod(SshJobCoordinator::class, 'captureTruncation');
        $jobs = app(SshJobCoordinator::class);
        $belowCap = 200;
        $atCap = 1048576;

        // The wrapper emits its durable script_exit marker AFTER waiting for
        // both readers. A non-125 status therefore proves capture completion.
        // Legacy or systemd-only terminal states carry no such evidence.
        $cases = [
            'completed below cap' => ['completed', 'script_exit', 0, $belowCap, true, false, false],
            'failed script below cap' => ['failed', 'script_exit', 7, $belowCap, true, false, false],
            'completed confirmed overflow' => ['completed', 'script_exit', 0, $atCap, true, true, true],
            'canceled confirmed overflow' => ['canceled', 'systemd_signal', null, $atCap, true, true, true],
            'canceled partial spool' => ['canceled', 'systemd_signal', null, $belowCap, true, false, null],
            'canceled with stale exit code' => ['canceled', 'script_exit', 0, $belowCap, true, false, null],
            'systemd timeout partial spool' => ['failed', 'systemd_timeout', null, $belowCap, true, false, null],
            'systemd signal partial spool' => ['failed', 'systemd_signal', null, $belowCap, true, false, null],
            'systemd exit without wrapper proof' => ['failed', 'systemd_exit-code', 9, $belowCap, true, false, null],
            'collector failure 125' => ['failed', 'script_exit', 125, $belowCap, true, false, null],
            'successful script exit 125 indistinguishable' => ['failed', 'script_exit', 125, $belowCap, true, false, null],
            'legacy full-size log without overflow marker' => ['completed', 'script_exit', 0, $atCap, true, false, null],
            'running short file eof' => ['running', null, null, $belowCap, true, false, null],
            'completed without stored-file eof' => ['completed', 'script_exit', 0, $belowCap, false, false, null],
            'short partial file with confirmed overflow' => ['failed', 'systemd_timeout', null, $belowCap, true, true, true],
        ];

        foreach ($cases as $label => [$status, $reason, $code, $size, $eof, $overflow, $expected]) {
            $record = (object) [
                'status' => $status,
                'terminal_reason' => $reason,
                'exit_code' => $code,
            ];
            self::assertSame($expected,
                $method->invoke($jobs, $record, $size, $eof, $overflow), $label);
        }
    }

    public function test_native_job_output_permission_error_is_redacted_in_activity_ai_and_admin(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $handler = app(SshJobMcpToolHandlers::class);
        $dispatch = new \ReflectionMethod(SshJobMcpToolHandlers::class, 'dispatch');
        $result = $dispatch->invoke(
            $handler, $owner, $target->target_id, 'ssh-job-output',
            static fn (): never => throw new SshTargetConnectionException('file_unavailable', [
                'exception_class' => FileSystemException::class,
                'source_error_code' => 3,
                'source_error_message' => 'Permission denied /var/log/ssh-job/stdout token=FIXTURE_SFTP_OUTPUT_SECRET',
            ]),
        );
        self::assertFalse($result['ok']);
        self::assertSame('file_unavailable', $result['error']['code']);
        self::assertStringNotContainsString('FIXTURE_SFTP_OUTPUT_SECRET', json_encode($result, JSON_THROW_ON_ERROR));
        $reference = $result['error']['diagnostic_reference'];
        $evidence = app(OperationDiagnosticsMcpToolHandlers::class)->read($owner, $reference);
        self::assertTrue($evidence['ok']);
        self::assertSame('ssh-job-output', $evidence['events'][0]['operation']);
        self::assertSame(3, $evidence['events'][0]['diagnostics']['source_error_code']);
        self::assertStringContainsString('Permission denied /var/log/ssh-job/stdout',
            $evidence['events'][0]['diagnostics']['source_error_message']);
        self::assertStringNotContainsString('FIXTURE_SFTP_OUTPUT_SECRET',
            json_encode($evidence, JSON_THROW_ON_ERROR));
        $stored = DB::table('activity_events')->where('correlation_id', $reference)->value('diagnostic_context');
        self::assertIsString($stored);
        self::assertStringNotContainsString('FIXTURE_SFTP_OUTPUT_SECRET', $stored);
        $this->actingAs($owner)->get('/admin/activity?diagnostic_reference='.$reference)
            ->assertOk()->assertSee($reference)
            ->assertSee('Permission denied /var/log/ssh-job/stdout')
            ->assertDontSee('FIXTURE_SFTP_OUTPUT_SECRET');
    }

    public function test_job_input_and_per_principal_active_admission_are_bounded(): void
    {
        $user = $this->user('owner');
        $target = $this->target();
        $tool = app(SshJobMcpToolHandlers::class);
        $client = hash('sha256', 'limit');
        foreach ([
            [str_repeat('a', 16385), 30],
            ["echo\0danger", 30],
            ['  ', 30],
            ['echo safe', 15],
            ['echo safe', 301],
        ] as [$script, $seconds]) {
            self::assertSame('invalid_input',
                $tool->start($user, $target->target_id, $client, (string) Str::uuid(), $script, $seconds)['error']['code']);
        }
        self::assertSame(0, DB::table('ssh_command_jobs')->count());

        $binding = hash('sha256', implode("\0", [
            (string) $target->getKey(), $target->target_id,
            'fixture.example.test', '22', 'fixture-user', 'password',
            'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32)),
        ]));
        for ($i = 0; $i < 2; $i++) {
            DB::table('ssh_command_jobs')->insert([
                'id' => (string) Str::ulid(),
                'target_record_id' => $target->getKey(),
                'user_id' => $user->getKey(),
                'client_identity_hash' => $client,
                'request_id' => (string) Str::uuid(),
                'script_digest' => str_repeat('a', 64),
                'target_binding_hash' => $binding,
                'status' => 'running',
                'runtime_seconds' => 60,
                'expires_at' => now()->addHour(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
        self::assertSame('rate_limited',
            $tool->start($user, $target->target_id, $client, (string) Str::uuid(), 'echo third')['error']['code']);
        self::assertSame(2, DB::table('ssh_command_jobs')->count());
    }

    public function test_job_output_admission_failure_has_one_authorized_canonical_activity_and_no_denial_flood(): void
    {
        $owner = $this->user('owner');
        $other = $this->user('operator');
        $target = $this->target();
        $client = hash('sha256', 'job-diagnostic-client');
        $jobs = app(SshJobMcpToolHandlers::class);
        // The synthetic host declines all outbound SSH, but its durable
        // unsupported handle is sufficient for a bounded read admission test.
        $created = $jobs->start($owner, $target->target_id, $client, (string) Str::uuid(), 'echo no-send');
        self::assertSame('unsupported', $created['result']['status']);
        $jobId = $created['result']['job_id'];
        $rateKey = 'ssh-file:'.hash('sha256', (string) $target->getKey()).':rate';
        RateLimiter::clear($rateKey);
        for ($i = 0; $i < 30; $i++) {
            RateLimiter::hit($rateKey, 60);
        }
        try {
            $before = DB::table('activity_events')->count();
            Log::spy();
            $denied = $jobs->output($owner, $target->target_id, $client, $jobId);
            self::assertFalse($denied['ok']);
            self::assertSame('rate_limited', $denied['error']['code']);
            $reference = $denied['error']['diagnostic_reference'];
            self::assertTrue(Str::isUuid($reference));
            self::assertSame($before + 1, DB::table('activity_events')->count());

            $read = app(OperationDiagnosticsMcpToolHandlers::class)->read($owner, $reference);
            self::assertTrue($read['ok']);
            self::assertCount(1, $read['events']);
            $event = $read['events'][0];
            self::assertSame('ssh-job-output', $event['operation']);
            self::assertSame($target->target_id, $event['target_id']);
            self::assertSame('rate_limited', $event['error_code']);
            self::assertSame('available', $event['diagnostic_state']);
            self::assertSame('gateway_admission', $event['diagnostics']['failure_origin']);
            self::assertSame('admission', $event['diagnostics']['failure_stage']);
            self::assertTrue($event['diagnostics']['request_not_sent']);
            self::assertTrue($event['diagnostics']['retry_safe']);

            // Wrong client/user and malformed identities never acquire a
            // privileged diagnostic reference or cause a new DB/log storm.
            foreach ([
                $jobs->output($other, $target->target_id, $client, $jobId),
                $jobs->output($owner, $target->target_id, hash('sha256', 'other-client'), $jobId),
                $jobs->output($owner, 'target-not-found', $client, $jobId),
            ] as $unavailable) {
                self::assertSame('target_not_found', $unavailable['error']['code']);
                self::assertArrayNotHasKey('diagnostic_reference', $unavailable['error']);
            }
            self::assertSame($before + 1, DB::table('activity_events')->count());
            self::assertSame(1, DB::table('ssh_command_jobs')->count());
            // This known, recorded pre-dispatch refusal does not emit a
            // duplicate per-attempt WARNING into the PHP daily log.
            Log::shouldNotHaveReceived('warning');
        } finally {
            RateLimiter::clear($rateKey);
        }
    }

    public function test_owner_script_budget_checks_actual_bytes_and_keeps_existing_uuid_durable_when_lowered(): void
    {
        $user = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'script-budget');
        DB::table('operational_settings')->where('id', 1)
            ->update(['ssh_job_max_script_kib' => 64]);
        $tool = app(SshJobMcpToolHandlers::class);
        $script = str_repeat('# padded script line'.chr(10), 1000).'echo safe';
        self::assertGreaterThan(16384, strlen($script));
        self::assertLessThanOrEqual(65536, strlen($script));

        $uuid = (string) Str::uuid();
        $first = $tool->start($user, $target->target_id, $client, $uuid, $script, 30);
        self::assertSame('job_unsupported', $first['error']['code']);
        self::assertSame('unsupported', $first['result']['status']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());

        foreach ([str_repeat('a', 65537), str_repeat('ی', 40000)] as $overlong) {
            self::assertSame('invalid_input', $tool->start(
                $user, $target->target_id, $client, (string) Str::uuid(), $overlong, 30,
            )['error']['code']);
        }
        self::assertSame(1, DB::table('ssh_command_jobs')->count());

        DB::table('operational_settings')->where('id', 1)
            ->update(['ssh_job_max_script_kib' => 16]);
        $this->app->forgetInstance(OperationalSettings::class);
        $this->app->forgetInstance(SshJobCoordinator::class);
        $this->app->forgetInstance(SshJobMcpToolHandlers::class);
        $tool = app(SshJobMcpToolHandlers::class);

        $same = $tool->start($user, $target->target_id, $client, $uuid, $script, 30);
        self::assertSame($first['result']['job_id'], $same['result']['job_id']);
        self::assertSame('invalid_input', $tool->start(
            $user, $target->target_id, $client, (string) Str::uuid(), $script, 30,
        )['error']['code']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
    }

    public function test_exact_512_kib_job_script_is_admitted_and_extra_utf8_byte_rejected_before_journal(): void
    {
        $user = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'job-script-512k');
        DB::table('operational_settings')->where('id', 1)->update(['ssh_job_max_script_kib' => 512]);
        $jobs = app(SshJobMcpToolHandlers::class);
        $prefix = 'echo approved'.chr(10);
        $script = $prefix.str_repeat('#', 524288 - strlen($prefix));
        self::assertSame(524288, strlen($script));
        $sameId = (string) Str::uuid();
        $started = $jobs->start($user, $target->target_id, $client, $sameId, $script, 30);
        self::assertSame('job_unsupported', $started['error']['code']);
        self::assertSame('unsupported', $started['result']['status']);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
        self::assertSame($started['result']['job_id'],
            $jobs->start($user, $target->target_id, $client, $sameId, $script, 30)['result']['job_id']);

        foreach ([$script.'x', str_repeat('é', 262145)] as $over) {
            $result = $jobs->start(
                $user, $target->target_id, $client, (string) Str::uuid(), $over, 30,
            );
            self::assertSame('invalid_input', $result['error']['code']);
        }
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
    }

    public function test_expired_unknown_job_stays_recoverable_and_does_not_get_replayed_or_pruned(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'client-once');
        $script = 'echo uncertain';
        $requestId = (string) Str::uuid();
        $id = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, $client, $requestId, $script,
        )['result']['job_id'];

        DB::table('ssh_command_jobs')->where('id', $id)->update([
            'status' => 'launch_unknown',
            'unit_mode' => 'user',
            'expires_at' => now()->subDay(),
        ]);
        $tool = app(SshJobMcpToolHandlers::class);
        self::assertSame($id, $tool->start(
            $owner, $target->target_id, $client, $requestId, $script,
        )['result']['job_id']);
        self::assertSame('launch_unknown',
            $tool->status($owner, $target->target_id, $client, $id)['result']['status']);
        $cancel = $tool->cancel($owner, $target->target_id, $client, $id);
        self::assertTrue($cancel['ok']);
        self::assertSame('cancel_requested', $cancel['result']['status']);
        self::assertFalse($cancel['result']['complete']);
        // The remote unit was uncontactable: a stop was not verified.
        self::assertSame(0, app(SshJobCoordinator::class)->prune());
        self::assertSame('cancel_requested', DB::table('ssh_command_jobs')->where('id', $id)->value('status'));
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
    }

    public function test_expired_unsupported_intent_prunes_without_remote_cleanup(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $client = hash('sha256', 'unsupported');
        $id = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, $client, (string) Str::uuid(), 'echo never-run',
        )['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update(['expires_at' => now()->subDay()]);
        self::assertSame(1, app(SshJobCoordinator::class)->prune());
        self::assertSame(0, DB::table('ssh_command_jobs')->count());
    }

    public function test_migration_rollback_refuses_to_discard_even_terminal_no_replay_handles(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $id = app(SshJobMcpToolHandlers::class)->start(
            $owner, $target->target_id, hash('sha256', 'rollback-client'),
            (string) Str::uuid(), 'echo already-done',
        )['result']['job_id'];
        DB::table('ssh_command_jobs')->where('id', $id)->update(['status' => 'completed']);

        $migration = require database_path('migrations/2026_10_15_010000_create_ssh_command_jobs.php');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Reconcile and prune every SSH Job');
        $migration->down();
    }

    public function test_public_manifest_advertises_bounded_job_family_with_correct_mutability(): void
    {
        $owner = $this->user('owner');
        $host = parse_url((string) config('oauth.resource'), PHP_URL_HOST);
        self::assertIsString($host);
        $headers = [
            'HTTP_HOST' => $host,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_MCP_PROTOCOL_VERSION' => '2025-11-25',
        ];
        $init = Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2025-11-25',
                'capabilities' => (object) [],
                'clientInfo' => ['name' => 'Job test', 'version' => '1.0'],
            ],
        ], JSON_THROW_ON_ERROR));
        $init->attributes->set('oauth_user', $owner);
        $init->attributes->set('oauth_client_id', 'client-test');
        $init->attributes->set('oauth_client_profile_key', 'chatgpt');
        $endpoint = app(GatewayMcpEndpoint::class);
        $response = $endpoint->handle($init);
        self::assertSame(200, $response->getStatusCode());
        $session = $response->headers->get('Mcp-Session-Id');
        self::assertNotEmpty($session);
        $headers['HTTP_MCP_SESSION_ID'] = $session;
        $list = Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/list', 'params' => (object) [],
        ], JSON_THROW_ON_ERROR));
        $list->attributes->set('oauth_user', $owner);
        $list->attributes->set('oauth_client_id', 'client-test');
        $list->attributes->set('oauth_client_profile_key', 'chatgpt');
        $listing = $endpoint->handle($list);
        ob_start();
        $listing->sendContent();
        $body = (string) ob_get_clean();
        $data = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        $byName = collect($data['result']['tools'])->keyBy('name');
        foreach (['ssh-job-start', 'ssh-jobs-list', 'ssh-job-status', 'ssh-job-output', 'ssh-job-cancel'] as $name) {
            self::assertTrue($byName->has($name));
        }
        self::assertSame(16384, $byName['ssh-job-start']['inputSchema']['properties']['script']['maxLength']);
        self::assertSame(300, $byName['ssh-job-start']['inputSchema']['properties']['max_runtime_seconds']['maximum']);
        self::assertFalse($byName['ssh-job-start']['annotations']['readOnlyHint']);
        self::assertTrue($byName['ssh-jobs-list']['annotations']['readOnlyHint']);
        self::assertFalse($byName['ssh-jobs-list']['annotations']['openWorldHint']);
        self::assertSame(50, $byName['ssh-jobs-list']['inputSchema']['properties']['limit']['maximum']);
        self::assertTrue($byName['ssh-job-status']['annotations']['readOnlyHint']);
        self::assertTrue($byName['ssh-job-cancel']['annotations']['destructiveHint']);
        self::assertStringContainsString('per call', $byName['ssh-job-output']['description']);
        self::assertStringContainsString('NOT an append/chunk upload', $byName['ssh-file-write']['description']);
        self::assertStringContainsString('separate from file-transfer/Job limits', $byName['ssh-command-run']['description']);

        // New MCP requests publish the current Owner-configured maximum,
        // never a hardcoded 300s schema that contradicts real runtime.
        DB::table('operational_settings')->where('id', 1)
            ->update(['ssh_job_max_runtime_seconds' => 7200, 'ssh_job_max_script_kib' => 512,
                'ssh_job_output_window_kib' => 512, 'ssh_file_read_window_kib' => 512,
                'ssh_file_write_window_kib' => 512, 'ssh_file_list_name_kib' => 512,
                'ssh_command_stdout_kib' => 512, 'ssh_command_stderr_kib' => 512,
                'ssh_command_timeout_seconds' => 360, 'ssh_command_max_kib' => 512]);
        // The test directly invokes the endpoint twice in one Laravel
        // container; in real HTTP handling scoped settings reset per request.
        $this->app->forgetInstance(OperationalSettings::class);
        $next = Request::create('/mcp', 'POST', [], [], [], $headers, json_encode([
            'jsonrpc' => '2.0', 'id' => 3, 'method' => 'tools/list', 'params' => (object) [],
        ], JSON_THROW_ON_ERROR));
        $next->attributes->set('oauth_user', $owner);
        $next->attributes->set('oauth_client_id', 'client-test');
        $next->attributes->set('oauth_client_profile_key', 'chatgpt');
        $updated = app(GatewayMcpEndpoint::class)->handle($next);
        ob_start();
        $updated->sendContent();
        $updatedData = json_decode((string) ob_get_clean(), true, 32, JSON_THROW_ON_ERROR);
        self::assertSame(200, $updated->getStatusCode());
        $changed = collect($updatedData['result']['tools'])->keyBy('name');
        self::assertSame(7200, $changed['ssh-job-start']['inputSchema']['properties']['max_runtime_seconds']['maximum']);
        self::assertSame(524288, $changed['ssh-job-start']['inputSchema']['properties']['script']['maxLength']);
        self::assertSame(360, $changed['ssh-command-run']['inputSchema']['properties']['timeout_seconds']['maximum']);
        self::assertSame(524288, $changed['ssh-command-run']['inputSchema']['properties']['command']['maxLength']);
        self::assertSame(524288, $changed['ssh-job-output']['inputSchema']['properties']['length']['maximum']);
        self::assertSame(524288, $changed['ssh-file-read']['inputSchema']['properties']['length']['maximum']);
        self::assertSame(699052, $changed['ssh-file-write']['inputSchema']['properties']['content_base64']['maxLength']);

        // Exercise the actual MCP tools/call transport envelope, not just
        // in-process handlers/schema. 512 KiB plain UTF-8 and canonical
        // Base64 must fit the Gateway's default 1 MiB inbound body budget.
        // This fixture's SSH egress is deterministically denied, so there
        // are no remote side effects or assumed client-host capabilities.
        $target = $this->target();
        // The registered policy contract requires a non-empty approved list;
        // a denied test destination must raise a typed denial, not return [].
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new SshTargetConnectionException('egress_denied');
            }
        });
        $call = function (string $name, array $arguments) use ($headers, $owner): array {
            $wire = json_encode([
                'jsonrpc' => '2.0', 'id' => 8, 'method' => 'tools/call',
                'params' => ['name' => $name, 'arguments' => $arguments],
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            self::assertLessThanOrEqual((int) config('oauth.mcp.max_body_bytes'), strlen($wire));
            $req = Request::create('/mcp', 'POST', [], [], [], [
                ...$headers, 'HTTP_MCP_METHOD' => 'tools/call',
                'HTTP_MCP_NAME' => $name,
            ], $wire);
            $req->attributes->set('oauth_user', $owner);
            $req->attributes->set('oauth_client_id', 'client-test');
            $req->attributes->set('oauth_client_profile_key', 'chatgpt');
            $reply = app(GatewayMcpEndpoint::class)->handle($req);
            self::assertSame(200, $reply->getStatusCode());
            ob_start();
            $reply->sendContent();

            return json_decode((string) ob_get_clean(), true, 32, JSON_THROW_ON_ERROR);
        };
        $command = $call('ssh-command-run', [
            'target_id' => $target->target_id, 'command' => str_repeat('x', 524288),
        ]);
        self::assertArrayHasKey('result', $command, json_encode($command, JSON_THROW_ON_ERROR));
        self::assertSame('egress_denied', $command['result']['structuredContent']['error']['code']);
        $encoded = base64_encode(str_repeat("\xff", 524288));
        // PHP's default JSON encoder escapes "/" in Base64 and can double
        // the whole request; that is correctly beyond the 1 MiB transport
        // budget. Callers must not confuse decoded bytes with wire bytes.
        self::assertGreaterThan((int) config('oauth.mcp.max_body_bytes'), strlen(json_encode([
            'method' => 'tools/call', 'params' => [
                'name' => 'ssh-file-write', 'arguments' => ['content_base64' => $encoded],
            ],
        ], JSON_THROW_ON_ERROR)));
        $write = $call('ssh-file-write', [
            'target_id' => $target->target_id, 'path' => '/tmp/mcp-boundary',
            'content_base64' => $encoded,
        ]);
        self::assertSame('egress_denied', $write['result']['structuredContent']['error']['code']);
        $job = $call('ssh-job-start', [
            'target_id' => $target->target_id, 'request_id' => (string) Str::uuid(),
            'script' => 'echo pass'.chr(10).str_repeat('#', 524288 - strlen('echo pass'.chr(10))),
        ]);
        self::assertSame('job_unsupported', $job['result']['structuredContent']['error']['code']);
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => $role,
            'email' => $role.'-job-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function target(): Target
    {
        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x52", 32),
        );
        $target = app(SshTargetRegistration::class)->register(
            'ssh-job-demo', 'SSH Job demo', 'fixture.example.test', 22,
            'fixture-user', $hostKey, 'password', 'test-secret', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
    }
}
