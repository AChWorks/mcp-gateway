<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\ChatGptFileToolAvailability;
use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\SshFileMcpToolHandlers;
use App\Application\Mcp\TargetFileInputMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use phpseclib4\Exception\FileSystemException;
use RuntimeException;
use Tests\TestCase;

final class SshFileMcpTest extends TestCase
{
    use RefreshDatabase;

    public function test_invalid_chatgpt_file_has_bounded_class_and_never_reaches_target_or_network(): void
    {
        Http::preventStrayRequests();
        $owner = $this->user('owner');
        $candidate = [
            'file_id' => 'secret-file-id',
            'download_url' => 'https://untrusted.example.test/private/file?token=secret-signature',
        ];

        $response = app(TargetFileInputMcpToolHandlers::class)->receive(
            $owner,
            'not-a-target',
            $candidate,
            'ssh_sftp_upload',
            ['path' => '/private/example.txt', 'private_staging_dir' => '/private/stage'],
        );

        self::assertFalse($response['ok']);
        self::assertSame('invalid_file_input', $response['error']['code']);
        self::assertSame('download_url_origin_denied', $response['error']['input_validation_class']);
        self::assertFalse($response['error']['retry_safe']);
        self::assertFalse($response['error']['possible_remote_effect'] ?? false);
        $public = json_encode($response, JSON_THROW_ON_ERROR);
        foreach (['secret-file-id', 'secret-signature', 'untrusted.example.test'] as $secret) {
            self::assertStringNotContainsString($secret, $public);
        }
        Http::assertNothingSent();
    }

    public function test_owner_only_missing_destination_probe_does_not_expose_secrets_or_effects(): void
    {
        Http::preventStrayRequests();
        Http::fake(static fn () => Http::response('unexpected', 200));
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $file = [
            'file_id' => 'sensitive-file-id',
            'download_url' => 'https://FILES.CHATGPT.COM/private/secret?sig=signed-secret',
        ];
        $handler = app(TargetFileInputMcpToolHandlers::class);
        $probe = $handler->receive($owner, 'tr01-test', $file, 'ssh_sftp_upload');

        self::assertSame('invalid_file_input', $probe['error']['code']);
        self::assertSame('download_url_origin_denied', $probe['error']['input_validation_class']);
        self::assertSame('files.chatgpt.com', $probe['error']['download_url_host']);
        self::assertFalse($probe['error']['retry_safe']);
        self::assertFalse($probe['error']['possible_remote_effect'] ?? false);
        $payload = json_encode($probe, JSON_THROW_ON_ERROR);
        foreach (['sensitive-file-id', 'signed-secret', '/private/secret'] as $private) {
            self::assertStringNotContainsString($private, $payload);
        }

        $destination = ['path' => '/private/test', 'private_staging_dir' => '/private/stage'];
        $ordinary = $handler->receive($owner, 'tr01-test', $file, 'ssh_sftp_upload', $destination);
        self::assertSame('invalid_file_input', $ordinary['error']['code']);
        self::assertArrayNotHasKey('download_url_host', $ordinary['error']);

        $operatorResult = $handler->receive($operator, 'tr01-test', $file, 'ssh_sftp_upload');
        self::assertArrayNotHasKey('download_url_host', $operatorResult['error']);

        $owner->forceFill(['access_enabled' => false])->save();
        $revoked = $handler->receive($owner, 'tr01-test', $file, 'ssh_sftp_upload');
        self::assertArrayNotHasKey('download_url_host', $revoked['error']);

        $wordpress = $handler->receive($operator, 'tr01-test', $file, 'wordpress_media_stage');
        self::assertArrayNotHasKey('download_url_host', $wordpress['error']);
        Http::assertNothingSent();
    }

    public function test_nonowners_stay_default_denied_and_unauthorized_targets_are_not_enumerable(): void
    {
        $operator = $this->user('operator');
        $owner = $this->user('owner');
        $target = $this->target();
        $wordpress = Target::query()->create([
            'target_id' => 'wp-sftp-mismatch', 'display_name' => 'WP', 'connector_type' => 'wp_ai_bridge',
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $files = app(SshFileMcpToolHandlers::class);
        $secret = '/home/secret-private-path';

        self::assertSame('target_not_found', $files->stat($operator, $target->target_id, $secret)['error']['code']);
        self::assertSame('target_not_found', $files->list($operator, $target->target_id, $secret)['error']['code']);
        self::assertSame('target_not_found', $files->read($operator, $target->target_id, $secret)['error']['code']);
        self::assertSame('target_not_found', $files->write($operator, $target->target_id, $secret, 'AA==')['error']['code']);
        self::assertSame('target_not_found', $files->stat($owner, $wordpress->target_id, '/')['error']['code']);
        self::assertSame('target_not_found', $files->stat($owner, '../ssh-file', '/')['error']['code']);
        self::assertSame('target_not_found', $files->stat($owner, 'missing-ssh-file', '/')['error']['code']);

        foreach (DB::table('activity_events')->where('operation', 'like', 'ssh-file-%')->get() as $event) {
            self::assertStringNotContainsString($secret, (string) json_encode($event, JSON_THROW_ON_ERROR));
        }
    }

    public function test_exact_read_write_permissions_are_independent_and_validation_precedes_transport(): void
    {
        $operator = $this->user('operator');
        $owner = $this->user('owner');
        $target = $this->target();
        // A previously successful pinned-host login is a prerequisite before
        // command/SFTP runtime reaches outbound egress policy.
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('Fixture: no remote network allowed.');
            }
        });

        $files = app(SshFileMcpToolHandlers::class);
        $id = $target->target_id;
        self::assertSame('invalid_input', $files->stat($owner, $id, '../etc/passwd')['error']['code']);
        self::assertSame('invalid_input', $files->list($owner, $id, '/', 101)['error']['code']);
        self::assertSame('invalid_input', $files->read($owner, $id, '/', -1)['error']['code']);
        self::assertSame('invalid_input', $files->read($owner, $id, '/', 0, 16385)['error']['code']);
        self::assertSame('invalid_input', $files->read($owner, $id, '/', 0, 1, 10)['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', '!!!!')['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', 'AA==', true, 1)['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', 'AA==', false, 1, 1)['error']['code']);
        self::assertSame('egress_denied', $files->write($owner, $id, '/sample', 'AA==', true)['error']['code']);
        self::assertSame('invalid_input', $files->write($owner, $id, '/sample', base64_encode(str_repeat('z', 16385)))['error']['code']);
        $stat = $files->stat($owner, $id, '/');
        self::assertSame('egress_denied', $stat['error']['code']);
        $diagnostics = app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($owner, $stat['error']['diagnostic_reference']);
        self::assertTrue($diagnostics['ok']);
        self::assertSame('gateway_admission', $diagnostics['events'][0]['diagnostics']['failure_origin']);
        self::assertSame('connection_setup', $diagnostics['events'][0]['diagnostics']['failure_stage']);
        self::assertTrue($diagnostics['events'][0]['diagnostics']['request_not_sent']);

        // Read only: the explicit global read grant cannot elevate write.
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshFileRead->value)->delete();
        self::assertSame('egress_denied', $files->read($operator, $id, '/sample')['error']['code']);
        self::assertSame('target_not_found', $files->write($operator, $id, '/sample', 'AA==')['error']['code']);

        // Explicit target-level denial prevents even an otherwise allowed read.
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshFileRead->value,
        ]);
        self::assertSame('target_not_found', $files->stat($operator, $id, '/')['error']['code']);
        DB::table('user_target_permission_denials')->where('user_id', $operator->getKey())->delete();

        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshFileWrite->value)->delete();
        self::assertSame('egress_denied', $files->write($operator, $id, '/sample', 'AA==')['error']['code']);
        $activity = (string) json_encode(DB::table('activity_events')->where('operation', 'like', 'ssh-file-%')->get(), JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('Fixture: no remote network allowed.', $activity);
        self::assertStringNotContainsString('/sample', $activity);

        // Internal (non-MCP) callers must not contact SSH for a revoked user.
        $owner->access_enabled = false;
        $owner->save();
        try {
            app(SshFileRuntime::class)->stat($owner, $target, '/sample');
            self::fail('Revoked principals must fail before remote transport.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_not_found', $exception->reason);
        }
    }

    public function test_sftp_effect_boundary_checks_fresh_target_and_user_permissions(): void
    {
        $operator = $this->user('operator');
        $target = $this->target();
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())
            ->where('permission', GatewayPermission::SshFileWrite->value)->delete();

        // Deliberately use the ORIGINAL, stale Eloquent instances at every
        // invocation. The new gate must re-read DB state before SFTP effects,
        // including for the non-MCP human channel.
        $guard = new \ReflectionMethod(SshFileRuntime::class, 'assertCurrentFileWriteAuthority');
        $runtime = app(SshFileRuntime::class);
        $guard->invoke($runtime, $operator, $target);

        $assertDenied = static function (string $reason) use ($guard, $runtime, $operator, $target): void {
            try {
                $guard->invoke($runtime, $operator, $target);
                self::fail('Stale actor or Target state cannot authorize a new SFTP effect.');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame($reason, $exception->reason);
            }
        };

        DB::table('targets')->where('id', $target->getKey())->update(['operations_paused' => true]);
        $assertDenied('target_paused');
        DB::table('targets')->where('id', $target->getKey())->update(['operations_paused' => false]);

        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'permission' => GatewayPermission::SshFileWrite->value,
        ]);
        $assertDenied('forbidden');
        DB::table('user_permission_denials')->where('user_id', $operator->getKey())->delete();

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshFileWrite->value,
        ]);
        $assertDenied('forbidden');
        DB::table('user_target_permission_denials')->where('user_id', $operator->getKey())->delete();

        $group = TargetGroup::query()->create(['name' => 'SSH group deny fixture']);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->getKey(), 'user_id' => $operator->getKey(),
        ]);
        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->getKey(), 'target_record_id' => $target->getKey(),
        ]);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::SshFileWrite->value,
        ]);
        $assertDenied('forbidden');
        DB::table('target_group_permission_denials')
            ->where('target_group_id', $group->getKey())->delete();

        DB::table('user_target_access')->where('user_id', $operator->getKey())
            ->where('target_record_id', $target->getKey())->update(['allowed' => false]);
        $assertDenied('forbidden');
        DB::table('user_target_access')->where('user_id', $operator->getKey())
            ->where('target_record_id', $target->getKey())->update(['allowed' => true]);

        DB::table('users')->where('id', $operator->getKey())->update(['access_enabled' => false]);
        $assertDenied('forbidden');
        DB::table('users')->where('id', $operator->getKey())->update(['access_enabled' => true]);

        DB::table('targets')->where('id', $target->getKey())
            ->update(['connection_state' => TargetConnectionState::Disconnected->value]);
        $assertDenied('forbidden');
        DB::table('targets')->where('id', $target->getKey())
            ->update(['connection_state' => TargetConnectionState::Connected->value]);

        $guard->invoke($runtime, $operator, $target);
    }

    public function test_chatgpt_ssh_file_input_denies_ungranted_paused_and_revoked_targets_before_signed_download(): void
    {
        config()->set('ssh.file_transfer.enabled', true);
        Http::preventStrayRequests();
        Http::fake(static fn (Request $request) => Http::response('must-not-fetch', 200));
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $target = $this->target();
        $handler = app(TargetFileInputMcpToolHandlers::class);
        $file = [
            'download_url' => 'https://files.oaiusercontent.com/private/secret?sig=opaque',
            'file_id' => 'file_secret',
        ];
        $destination = [
            'path' => '/home/deploy/test.bin',
            'private_staging_dir' => '/home/deploy/.private',
        ];

        $forbidden = $handler->receive($operator, $target->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_found', $forbidden['error']['code']);
        $target->forceFill(['operations_paused' => true])->save();
        $paused = $handler->receive($owner, $target->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_paused', $paused['error']['code']);
        $target->forceFill(['operations_paused' => false])->save();

        $owner->forceFill(['access_enabled' => false])->save();
        $revoked = $handler->receive($owner, $target->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_found', $revoked['error']['code']);
        Http::assertNothingSent();
    }

    public function test_chatgpt_selected_ssh_target_must_be_connected_and_have_verified_local_credentials_before_signed_get(): void
    {
        // This legacy FileParams implementation regression intentionally
        // exercises the preserved opt-in path; production defaults to OFF.
        config()->set('bridge.file_input.enabled', true);
        config()->set('ssh.file_transfer.enabled', true);
        Http::preventStrayRequests();
        Http::fake(static fn (Request $request) => Http::response('not-expected', 200));
        $owner = $this->user('owner');
        $ready = $this->target();
        $ready->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $handler = app(TargetFileInputMcpToolHandlers::class);

        $file = [
            'download_url' => 'https://files.oaiusercontent.com/private/signed?sig=secret',
            'file_id' => 'file_unauthorized_unavailable_target',
        ];
        $destination = ['path' => '/srv/selected/never.bin', 'private_staging_dir' => '/srv/selected/.private'];

        // Another eligible Target may keep the global FileParams Tool visible.
        self::assertTrue(app(ChatGptFileToolAvailability::class)
            ->modes($owner, 'chatgpt')['ssh']);

        $register = static fn (string $id): Target => app(SshTargetRegistration::class)->register(
            $id, 'Unavailable SSH', '127.0.0.1', 22, 'deploy',
            'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32)),
            'password', 'fixture-only-password', null,
        );

        $disconnected = $register('ssh-file-disconnected');
        $result = $handler->receive($owner, $disconnected->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_connected', $result['error']['code']);
        self::assertFalse($result['error']['possible_remote_effect'] ?? false);

        $disconnected->forceFill(['connection_state' => TargetConnectionState::ReconnectRequired])->save();
        $reconnect = $handler->receive($owner, $disconnected->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_connected', $reconnect['error']['code']);

        $noConfig = $register('ssh-file-noconfig');
        $noConfig->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $noConfig->sshConfig()->delete();
        $configFailure = $handler->receive($owner, $noConfig->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_connected', $configFailure['error']['code']);

        $noCredentials = $register('ssh-file-nocreds');
        $noCredentials->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $noCredentials->credentials()->delete();
        $credentialFailure = $handler->receive($owner, $noCredentials->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_connected', $credentialFailure['error']['code']);

        $invalidCredentials = $register('ssh-file-badcreds');
        $invalidCredentials->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('target_credentials')->where('target_record_id', $invalidCredentials->getKey())
            ->update(['encrypted_payload' => 'invalid-ciphertext']);
        $invalid = $handler->receive($owner, $invalidCredentials->target_id, $file, 'ssh_sftp_upload', $destination);
        self::assertSame('target_not_connected', $invalid['error']['code']);

        Http::assertNothingSent();
        self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());
        self::assertSame(0, DB::table('activity_events')->where('operation', 'mcp-file-upload')->count());
    }

    public function test_native_sftp_status_keeps_original_error_fields_only_in_redacted_diagnostics(): void
    {
        // Pure in-process fixture: no SFTP transport, server write, or secrets.
        $observed = new FileSystemException(
            'Permission denied /var/log/service.log; token=FIXTURE_SECRET_999', 3,
        );
        $convert = new \ReflectionMethod(SshFileRuntime::class, 'observedSftpFailure');
        $error = $convert->invoke(app(SshFileRuntime::class), $observed);
        self::assertInstanceOf(SshTargetConnectionException::class, $error);
        self::assertSame('file_unavailable', $error->reason);
        self::assertSame('SSH connection cannot be completed safely.', $error->getMessage());
        $safe = OperationDiagnostics::safeContext($error->diagnostics);
        self::assertSame(3, $safe['source_error_code']);
        self::assertSame('operation', $safe['failure_stage']);
        self::assertStringContainsString('/var/log/service.log', $safe['source_error_message']);
        self::assertStringNotContainsString('FIXTURE_SECRET_999', $safe['source_error_message']);
        self::assertStringContainsString('token=[REDACTED]', $safe['source_error_message']);
    }

    public function test_write_preflight_preserves_native_status_without_fabricating_source_changes(): void
    {
        $runtime = app(SshFileRuntime::class);
        $classify = new \ReflectionMethod(SshFileRuntime::class, 'writePreflightFailure');
        $denied = new FileSystemException(
            'Permission denied /var/reports/report.txt token=FIXTURE_WRITE_SECRET', 3,
        );
        foreach ([false, true] as $overwrite) {
            $error = $classify->invoke($runtime, $denied, $overwrite);
            self::assertInstanceOf(SshTargetConnectionException::class, $error);
            self::assertSame('file_unavailable', $error->reason);
            self::assertSame(3, $error->diagnostics['source_error_code']);
            self::assertStringContainsString('Permission denied /var/reports/report.txt',
                $error->diagnostics['source_error_message']);
            self::assertSame('SSH connection cannot be completed safely.', $error->getMessage());
        }
        foreach ([2, 10] as $missingCode) {
            $missing = new FileSystemException('No such destination /var/reports/report.txt', $missingCode);
            self::assertNull($classify->invoke($runtime, $missing, false),
                'Only native missing paths can proceed to create-only staging.');
            $replaced = $classify->invoke($runtime, $missing, true);
            self::assertSame('source_changed', $replaced->reason);
            self::assertSame($missingCode, $replaced->diagnostics['source_error_code']);
            self::assertStringContainsString('/var/reports/report.txt',
                $replaced->diagnostics['source_error_message']);
        }
        $unexpected = new FileSystemException('Native SFTP failure, cause unexpected', 11);
        self::assertSame('file_unavailable', $classify->invoke($runtime, $unexpected, true)->reason);
        self::assertSame(11, $classify->invoke($runtime, $unexpected, false)->diagnostics['source_error_code']);
    }

    public function test_staged_write_native_failure_stays_unknown_and_exposes_only_redacted_admin_ai_evidence(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $runtime = app(SshFileRuntime::class);
        $detailsMethod = new \ReflectionMethod(SshFileRuntime::class, 'writeStagingDiagnostics');
        $original = new FileSystemException(
            'Permission denied /srv/remote/output.log password=FIXTURE_STAGE_SECRET_333', 3,
        );
        $details = $detailsMethod->invoke($runtime, $original);
        self::assertSame(3, $details['source_error_code']);
        self::assertSame('unknown', $details['failure_origin']);
        self::assertSame('operation', $details['failure_stage']);
        self::assertTrue($details['effect_unconfirmed']);
        self::assertFalse($details['retry_safe']);
        self::assertStringContainsString('Permission denied /srv/remote/output.log',
            $details['source_error_message']);
        self::assertStringNotContainsString('FIXTURE_STAGE_SECRET_333',
            json_encode($details, JSON_THROW_ON_ERROR));
        self::assertStringContainsString('password=[REDACTED]', $details['source_error_message']);

        $dispatch = new \ReflectionMethod(SshFileMcpToolHandlers::class, 'dispatch');
        $result = $dispatch->invoke(
            app(SshFileMcpToolHandlers::class), $owner, $target->target_id,
            'ssh-file-write', GatewayPermission::SshFileWrite,
            static fn (Target $target): array => [
                'status' => 'outcome_unknown',
                'complete' => false,
                'possible_remote_effect' => true,
                'temporary_cleanup_confirmed' => false,
                '__diagnostic_context' => $details,
            ],
        );
        self::assertFalse($result['ok']);
        self::assertSame('outcome_unknown', $result['error']['code']);
        self::assertFalse($result['result']['complete']);
        self::assertTrue($result['result']['possible_remote_effect']);
        self::assertArrayNotHasKey('__diagnostic_context', $result['result']);
        self::assertStringNotContainsString('Permission denied',
            json_encode($result, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('FIXTURE_STAGE_SECRET_333',
            json_encode($result, JSON_THROW_ON_ERROR));
        $reference = $result['error']['diagnostic_reference'];
        $stored = DB::table('activity_events')->where('correlation_id', $reference)->first();
        self::assertNotNull($stored);
        self::assertSame('unknown', $stored->outcome);
        self::assertSame('outcome_unknown', $stored->error_code);
        self::assertStringNotContainsString('FIXTURE_STAGE_SECRET_333', $stored->diagnostic_context);
        $ai = app(OperationDiagnosticsMcpToolHandlers::class)->read($owner, $reference);
        self::assertTrue($ai['ok']);
        self::assertSame(3, $ai['events'][0]['diagnostics']['source_error_code']);
        self::assertSame('Permission denied /srv/remote/output.log password=[REDACTED]',
            $ai['events'][0]['diagnostics']['source_error_message']);
        self::assertFalse($ai['events'][0]['diagnostics']['retry_safe']);
        $this->actingAs($owner)->get('/admin/activity?diagnostic_reference='.$reference)
            ->assertOk()->assertSee($reference)
            ->assertSee('Permission denied /srv/remote/output.log')
            ->assertDontSee('FIXTURE_STAGE_SECRET_333');

        // No provider cause is invented when a generic runtime error has no
        // verifiable native code; effects remain uncertain and non-retryable.
        $unknown = $detailsMethod->invoke($runtime, new RuntimeException('token=FIXTURE_UNKNOWN_SECRET'));
        self::assertSame('unknown', $unknown['provider_cause']);
        self::assertArrayNotHasKey('source_error_code', $unknown);
        self::assertArrayNotHasKey('source_error_message', $unknown);
        self::assertFalse($unknown['retry_safe']);
        self::assertTrue($unknown['effect_unconfirmed']);
        self::assertStringNotContainsString('FIXTURE_UNKNOWN_SECRET', json_encode($unknown));
    }

    public function test_owner_configured_exact_512_kib_inline_sftp_windows_enforce_decoded_bytes(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_file_read_window_kib' => 512,
            'ssh_file_write_window_kib' => 512,
            'ssh_file_list_name_kib' => 512,
        ]);
        $this->app->forgetInstance(OperationalSettings::class);
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new RuntimeException('No network permitted in payload boundary test.');
            }
        });
        $tools = app(SshFileMcpToolHandlers::class);
        self::assertSame('egress_denied',
            $tools->read($owner, $target->target_id, '/tmp/fixture', 0, 524288)['error']['code']);
        self::assertSame('invalid_input',
            $tools->read($owner, $target->target_id, '/tmp/fixture', 0, 524289)['error']['code']);

        $encoded = base64_encode(str_repeat("\xff", 524288));
        self::assertSame(699052, strlen($encoded));
        self::assertSame('egress_denied',
            $tools->write($owner, $target->target_id, '/tmp/fixture', $encoded)['error']['code']);
        self::assertSame('invalid_input',
            $tools->write($owner, $target->target_id, '/tmp/fixture', base64_encode(str_repeat('x', 524289)))['error']['code']);
        self::assertSame('invalid_input',
            $tools->write($owner, $target->target_id, '/tmp/fixture', $encoded.'==')['error']['code']);

        // Internal stream buffers and aggregate SSH whole-file size retain
        // their independent budgets despite the enlarged inline window.
        self::assertSame(8388608, app(OperationalSettings::class)->sshTransferLimits()['max_bytes']);
    }

    private function target(): Target
    {
        return app(SshTargetRegistration::class)->register(
            'ssh-file', 'SSH file', '127.0.0.1', 22, 'deploy',
            'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32)),
            'password', 'fixture-only-password', null,
        );
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => $role,
            'email' => Str::random(14).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }
}
