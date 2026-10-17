<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshFileMcpToolHandlers;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class OperationDiagnosticsLookupTest extends TestCase
{
    use RefreshDatabase;

    public function test_safe_context_reaches_both_admin_and_ai_without_secret_leaks(): void
    {
        $owner = $this->user('owner', 'all');
        $target = $this->target('wp-test', 'wp_ai_bridge');
        $reference = (string) Str::uuid();
        app(ActivityRecorder::class)->record($reference, 'wordpress-ability-execute', 'unknown', $target, 'downstream_rejected', [
            'failure_origin' => 'downstream_mcp',
            'failure_stage' => 'operation',
            'provider_cause_unknown' => true,
            'effect_unconfirmed' => true,
            'retry_safe' => true,
            'token' => 'PRIVATE_TOKEN',
            'response_body' => 'PRIVATE_WORDPRESS_RESPONSE',
        ]);
        $record = (string) DB::table('activity_events')->where('correlation_id', $reference)->value('diagnostic_context');
        self::assertStringNotContainsString('PRIVATE_TOKEN', $record);
        self::assertStringNotContainsString('PRIVATE_WORDPRESS_RESPONSE', $record);
        $safe = json_decode($record, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('downstream_mcp', $safe['failure_origin']);
        self::assertSame('operation', $safe['failure_stage']);
        self::assertSame('unknown', $safe['provider_cause']);
        self::assertFalse($safe['retry_safe']);
        $result = app(OperationDiagnosticsMcpToolHandlers::class)->read($owner, $reference);
        self::assertTrue($result['ok']);
        self::assertSame($safe, $result['events'][0]['diagnostics']);
        self::assertSame('unknown', $result['events'][0]['outcome']);
        self::assertArrayNotHasKey('actor_id', $result['events'][0]);
        $this->actingAs($owner)->get('/admin/activity?diagnostic_reference='.$reference)
            ->assertOk()->assertSee($reference)->assertSee('downstream_mcp')
            ->assertDontSee('PRIVATE_TOKEN');
    }

    public function test_escaped_secrets_cannot_leak_via_activity_logs_admin_or_mcp(): void
    {
        $owner = $this->user('owner', 'all');
        $target = $this->target('wp-sensitive', 'wp_ai_bridge');
        $reference = (string) Str::uuid();
        $json = str_replace('"', '\\"', json_encode([
            'password' => 'SECRET_ESCAPED_FIELD_VALUE',
        ], JSON_THROW_ON_ERROR));

        $escapedUri = json_encode([
            'endpoint' => 'sftp://svc:ACTIVITY_ESCAPED_SECRET_717@files.example.test/trace/error.log',
        ], JSON_THROW_ON_ERROR);
        $doubleEscapedUri = json_encode($escapedUri, JSON_THROW_ON_ERROR);

        Log::spy();
        app(ActivityRecorder::class)->record($reference, 'wordpress-ability-execute',
            'failure', $target, 'downstream_rejected', [
                'failure_origin' => 'downstream_mcp',
                'failure_stage' => 'operation',
                'source_error_message' => 'Error in /app/provider.php: '.$json
                    .' [\'token\' => \'SECRET_QUOTED_VALUE\'] '
                    .'sftp://logs:SFTP_SECRET_231@files.example.test/trace/provider.log '
                    .'https://bucket.example.test/object?X-Amz-Signature=AMZ_SIGNATURE_232'
                    .'&X-Amz-Date=20261017T050000Z '.$escapedUri,
                'source_error_details' => [
                    'Bearer SECRET_IN_STRUCTURED_KEY' => 'SECRET_KEY_VALUE',
                    'raw_response' => 'SECRET_RAW_PAYLOAD',
                    'code' => 'provider/native-specific-422',
                    'signed_url' => 'https://storage.example.test/file?X-Goog-Signature=GOOG_SIGNATURE_234'
                        .'&response-content-type=application/json',
                    'database_url' => 'mysql://audit:MYSQL_SECRET_233@db.example.test/retention',
                    'serialized_error' => [
                        'observed_text' => $doubleEscapedUri,
                    ],
                    'remote_error' => [
                        'X-Amz-Signature' => 'STRUCTURED_AMZ_SIGNATURE_235',
                        'X-Goog-Signature' => 'STRUCTURED_GOOG_SIGNATURE_236',
                        'X-Amz-Date' => '20261017T050000Z',
                    ],
                ],
            ]);

        Log::shouldHaveReceived('warning')->once()
            ->withArgs(static function (string $message, array $context): bool {
                $logged = json_encode($context, JSON_THROW_ON_ERROR);

                return $message === 'Gateway operation failure.'
                    && ($context['source_error_details']['code'] ?? null) === 'provider/native-specific-422'
                    && ($context['source_error_details']['remote_error']['X-Amz-Date'] ?? null)
                        === '20261017T050000Z'
                    && ! str_contains($logged, 'SECRET_')
                    && ! str_contains($logged, 'SIGNATURE_')
                    && ! str_contains($logged, 'MYSQL_SECRET_')
                    && ! str_contains($logged, 'ACTIVITY_ESCAPED_SECRET_717');
            });

        $stored = (string) DB::table('activity_events')
            ->where('correlation_id', $reference)->value('diagnostic_context');
        $lookup = app(OperationDiagnosticsMcpToolHandlers::class)->read($owner, $reference);
        self::assertTrue($lookup['ok']);
        $adminResponse = $this->actingAs($owner)
            ->get('/admin/activity?diagnostic_reference='.$reference)->assertOk();
        $mcpPayload = json_encode($lookup, JSON_THROW_ON_ERROR);
        foreach ([
            'SECRET_ESCAPED_FIELD_VALUE', 'SECRET_QUOTED_VALUE',
            'SECRET_IN_STRUCTURED_KEY', 'SECRET_KEY_VALUE', 'SECRET_RAW_PAYLOAD',
            'SFTP_SECRET_231', 'AMZ_SIGNATURE_232', 'MYSQL_SECRET_233',
            'GOOG_SIGNATURE_234', 'STRUCTURED_AMZ_SIGNATURE_235',
            'STRUCTURED_GOOG_SIGNATURE_236', 'ACTIVITY_ESCAPED_SECRET_717',
        ] as $secret) {
            self::assertStringNotContainsString($secret, $stored);
            self::assertStringNotContainsString($secret, $mcpPayload);
            $adminResponse->assertDontSee($secret);
        }
        self::assertStringContainsString('/app/provider.php',
            $lookup['events'][0]['diagnostics']['source_error_message']);
        self::assertSame('provider/native-specific-422',
            $lookup['events'][0]['diagnostics']['source_error_details']['code']);
        self::assertStringContainsString('sftp://[REDACTED]@files.example.test/trace/provider.log',
            $lookup['events'][0]['diagnostics']['source_error_message']);
        self::assertStringContainsString('X-Amz-Date=20261017T050000Z',
            $lookup['events'][0]['diagnostics']['source_error_message']);
        $maskedEscapedUri = str_replace(
            'svc:ACTIVITY_ESCAPED_SECRET_717@', '[REDACTED]@', $escapedUri);
        self::assertStringContainsString($maskedEscapedUri,
            $lookup['events'][0]['diagnostics']['source_error_message']);
        self::assertSame(json_encode($maskedEscapedUri, JSON_THROW_ON_ERROR),
            $lookup['events'][0]['diagnostics']['source_error_details']['serialized_error']['observed_text']);
        self::assertStringContainsString('response-content-type=application/json',
            $lookup['events'][0]['diagnostics']['source_error_details']['signed_url']);
        self::assertSame('20261017T050000Z',
            $lookup['events'][0]['diagnostics']['source_error_details']['remote_error']['X-Amz-Date']);
        self::assertSame('[REDACTED]',
            $lookup['events'][0]['diagnostics']['source_error_details']['remote_error']['X-Goog-Signature']);
        self::assertSame($lookup['events'][0]['diagnostics'],
            OperationDiagnostics::safeContext($lookup['events'][0]['diagnostics']));
    }

    public function test_target_and_activity_view_scope_apply_to_ai_and_admin_lookup(): void
    {
        $operator = $this->user('operator', 'selected');
        $this->asOauthActor($operator);
        $alpha = $this->target('alpha', 'wp_ai_bridge');
        $beta = $this->target('beta', 'ssh_direct');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $alpha->getKey(), 'allowed' => true,
        ]);
        $recorder = app(ActivityRecorder::class);
        $a = (string) Str::uuid();
        $b = (string) Str::uuid();
        $global = (string) Str::uuid();
        $recorder->record($a, 'wordpress-ability-execute', 'failure', $alpha, 'downstream_rejected');
        $recorder->record($b, 'ssh-file-read', 'failure', $beta, 'rate_limited');
        $recorder->record($global, 'oauth', 'failure', null, 'server_error');
        $recorder->record((string) Str::uuid(), 'wordpress-ability-execute', 'success', $alpha);
        $tool = app(OperationDiagnosticsMcpToolHandlers::class);
        self::assertTrue($this->readAsOAuth($operator, $a)['ok']);
        $recent = $this->readAsOAuth($operator, null, 'alpha');
        self::assertTrue($recent['ok']);
        self::assertSame('recent_target_errors', $recent['lookup_mode']);
        self::assertSame('alpha', $recent['target_id']);
        self::assertCount(1, $recent['events']);
        self::assertSame($a, $recent['events'][0]['diagnostic_reference']);
        $hidden = $this->readAsOAuth($operator, $b);
        self::assertSame('diagnostic_unavailable', $hidden['error']['code']);
        self::assertSame($hidden, $this->readAsOAuth($operator, $global));
        self::assertSame($hidden, $this->readAsOAuth($operator, (string) Str::uuid()));
        self::assertSame($hidden, $this->readAsOAuth($operator, 'invalid'));
        self::assertSame($hidden, $this->readAsOAuth($operator, null, 'beta'));
        self::assertSame($hidden, $this->readAsOAuth($operator, null, 'not-a-target'));
        self::assertSame($hidden, $this->readAsOAuth($operator));
        $this->actingAs($operator)->get('/admin/activity?diagnostic_reference='.$b)
            ->assertOk()->assertSee('No activity matches these filters.');
        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::ActivityView->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        self::assertSame($hidden, $this->readAsOAuth($operator, $a));
        $this->actingAs($operator)->get('/admin/activity')->assertForbidden();
    }

    public function test_direct_and_group_activity_denials_hide_error_details_from_admin_and_ai(): void
    {
        $operator = $this->user('operator', 'selected');
        $this->asOauthActor($operator);
        $alpha = $this->target('alpha', 'wp_ai_bridge');
        $beta = $this->target('beta', 'ssh_direct');
        foreach ([$alpha, $beta] as $target) {
            DB::table('user_target_access')->insert([
                'user_id' => $operator->getKey(),
                'target_record_id' => $target->getKey(),
                'allowed' => true,
                'created_at' => now(), 'updated_at' => now(),
            ]);
        }

        $alphaRef = (string) Str::uuid();
        $betaRef = (string) Str::uuid();
        $recorder = app(ActivityRecorder::class);
        $recorder->record($alphaRef, 'wordpress-ability-execute', 'failure', $alpha,
            'downstream_rejected', ['source_error_message' => 'Internal PHP error at /site/wp/alpha.php']);
        $recorder->record($betaRef, 'ssh-file-read', 'failure', $beta,
            'rate_limited', ['source_error_message' => 'SSH error at /root/beta/file.log']);

        $diagnostics = app(OperationDiagnosticsMcpToolHandlers::class);
        self::assertTrue($this->readAsOAuth($operator, $alphaRef)['ok']);
        self::assertTrue($this->readAsOAuth($operator, $betaRef)['ok']);
        $unavailable = $this->readAsOAuth($operator, (string) Str::uuid());

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $alpha->getKey(),
            'permission' => GatewayPermission::ActivityView->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        self::assertSame($unavailable, $this->readAsOAuth($operator, $alphaRef));
        self::assertSame($unavailable, $this->readAsOAuth($operator, null, 'alpha'));
        self::assertTrue($this->readAsOAuth($operator, $betaRef)['ok']);
        $this->actingAs($operator)->get('/admin/activity?target_id=alpha')
            ->assertOk()->assertSee('No activity matches these filters.')
            ->assertDontSee('Internal PHP error at /site/wp/alpha.php');
        $this->actingAs($operator)->get('/admin/activity')
            ->assertOk()->assertDontSee('Internal PHP error at /site/wp/alpha.php')
            ->assertSee('SSH error at /root/beta/file.log');

        // The original Activity permission is restored on alpha, but a
        // group-scoped Activity denial hides beta independently of TargetsView.
        DB::table('user_target_permission_denials')
            ->where('user_id', $operator->getKey())
            ->where('target_record_id', $alpha->getKey())
            ->delete();
        self::assertTrue($this->readAsOAuth($operator, $alphaRef)['ok']);

        $groupId = (string) Str::ulid();
        DB::table('target_groups')->insert([
            'id' => $groupId, 'name' => 'Hidden diagnostics group',
            'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('target_group_targets')->insert([
            'target_group_id' => $groupId, 'target_record_id' => $beta->getKey(),
            'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('target_group_users')->insert([
            'target_group_id' => $groupId, 'user_id' => $operator->getKey(),
            'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $groupId,
            'permission' => GatewayPermission::ActivityView->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        self::assertSame($unavailable, $this->readAsOAuth($operator, $betaRef));
        self::assertSame($unavailable, $this->readAsOAuth($operator, null, 'beta'));
        self::assertTrue($this->readAsOAuth($operator, $alphaRef)['ok']);
        $this->actingAs($operator)->get('/admin/activity?diagnostic_reference='.$betaRef)
            ->assertOk()->assertSee('No activity matches these filters.')
            ->assertDontSee('/root/beta/file.log');

        // The user may still see the Target's existence if TargetsView is
        // allowed; denial is for its diagnostic content, not Target metadata.
        self::assertTrue(app(AccessControl::class)
            ->allows($operator, GatewayPermission::TargetsView, $beta));
    }

    public function test_actual_ssh_mcp_admission_errors_are_recoverable_without_dialing_a_host(): void
    {
        $owner = $this->user('owner', 'all');
        $target = $this->target('ssh-diagnostic', 'ssh_direct');
        $recordId = (string) $target->getKey();
        $fileKey = 'ssh-file:'.hash('sha256', $recordId).':rate';
        $commandKey = 'ssh-command:'.hash('sha256', $recordId).':rate';

        // Exhaust the *actual* admission budget, so no socket or credential
        // lookup can occur. This tests the real handlers, not a synthetic row.
        foreach ([$fileKey, $commandKey] as $key) {
            RateLimiter::clear($key);
            for ($i = 0; $i < 30; $i++) {
                RateLimiter::hit($key, 60);
            }
        }

        try {
            $file = app(SshFileMcpToolHandlers::class)
                ->stat($owner, $target->target_id, '/tmp/nonexistent-diagnostic-fixture');
            $command = app(SshCommandMcpToolHandlers::class)
                ->run($owner, $target->target_id, 'echo should-not-run');

            foreach ([$file, $command] as $error) {
                self::assertFalse($error['ok']);
                self::assertSame('rate_limited', $error['error']['code']);
                self::assertTrue(Str::isUuid($error['error']['diagnostic_reference']));
                $result = app(OperationDiagnosticsMcpToolHandlers::class)
                    ->read($owner, $error['error']['diagnostic_reference']);
                self::assertTrue($result['ok']);
                self::assertNotEmpty($result['events']);
                foreach ($result['events'] as $event) {
                    self::assertSame('gateway_admission', $event['diagnostics']['failure_origin']);
                    self::assertSame('admission', $event['diagnostics']['failure_stage']);
                    self::assertTrue($event['diagnostics']['request_not_sent']);
                    self::assertTrue($event['diagnostics']['retry_safe']);
                }
            }
        } finally {
            RateLimiter::clear($fileKey);
            RateLimiter::clear($commandKey);
        }
    }

    public function test_legacy_or_deleted_diagnostic_evidence_is_honestly_reported(): void
    {
        $owner = $this->user('owner', 'all');
        $ref = (string) Str::uuid();
        app(ActivityRecorder::class)->record($ref, 'ssh-file-read', 'failure', $this->target('ssh', 'ssh_direct'), 'rate_limited');
        $tool = app(OperationDiagnosticsMcpToolHandlers::class);
        self::assertSame('not_recorded_or_expired', $tool->read($owner, $ref)['events'][0]['diagnostic_state']);
        DB::table('activity_events')->where('correlation_id', $ref)->delete();
        self::assertSame('diagnostic_unavailable', $tool->read($owner, $ref)['error']['code']);
    }

    public function test_nonowner_mcp_diagnostics_are_isolated_by_actor_client_and_profile(): void
    {
        $alice = $this->user('operator', 'all');
        $bob = $this->user('operator', 'all');
        $owner = $this->user('owner', 'all');
        $target = $this->target('shared-wp', 'wp_ai_bridge');
        $references = [];

        foreach ([
            ['alice-first', $alice, 'first-client', 'chatgpt'],
            ['bob-first', $bob, 'first-client', 'chatgpt'],
            ['alice-second', $alice, 'second-client', 'fixture'],
        ] as [$label, $actor, $client, $profile]) {
            $this->asOauthActor($actor, $client, $profile);
            $references[$label] = (string) Str::uuid();
            app(ActivityRecorder::class)->record(
                $references[$label], 'wordpress-ability-execute', 'failure',
                $target, 'downstream_rejected',
                ['source_error_message' => 'Owned by '.$label.' at /var/www/wp/file.php'],
            );
        }

        $diagnostics = app(OperationDiagnosticsMcpToolHandlers::class);
        $aliceClientOne = fn (?string $reference = null) => $diagnostics->read(
            $alice, $reference, $reference === null ? 'shared-wp' : null, 1, 'first-client', 'chatgpt',
        );
        $aliceClientTwo = fn (?string $reference = null) => $diagnostics->read(
            $alice, $reference, $reference === null ? 'shared-wp' : null, 1, 'second-client', 'fixture',
        );
        $bobClientOne = fn (?string $reference = null) => $diagnostics->read(
            $bob, $reference, $reference === null ? 'shared-wp' : null, 1, 'first-client', 'chatgpt',
        );

        self::assertTrue($aliceClientOne($references['alice-first'])['ok']);
        self::assertTrue($aliceClientTwo($references['alice-second'])['ok']);
        self::assertTrue($bobClientOne($references['bob-first'])['ok']);

        foreach ([
            $aliceClientOne($references['bob-first']),
            $aliceClientOne($references['alice-second']),
            $aliceClientTwo($references['alice-first']),
            $bobClientOne($references['alice-first']),
            $diagnostics->read($alice, $references['alice-first']),
            $diagnostics->read($alice, $references['alice-first'], null, 1, 'first-client', 'fixture'),
        ] as $denied) {
            self::assertSame('diagnostic_unavailable', $denied['error']['code']);
        }
        self::assertSame([$references['alice-first']],
            array_column($aliceClientOne()['events'], 'diagnostic_reference'));
        self::assertSame([$references['alice-second']],
            array_column($aliceClientTwo()['events'], 'diagnostic_reference'));
        self::assertSame([$references['bob-first']],
            array_column($bobClientOne()['events'], 'diagnostic_reference'));

        // Owner keeps the existing explicit recovery authority.
        foreach ($references as $reference) {
            self::assertTrue($diagnostics->read($owner, $reference)['ok']);
        }

        $globalRef = (string) Str::uuid();
        $this->asOauthActor($bob, 'first-client', 'chatgpt');
        app(ActivityRecorder::class)->record($globalRef, 'oauth', 'failure', null, 'server_error',
            ['source_error_message' => 'Private OAuth setup error']);
        self::assertSame('diagnostic_unavailable', $aliceClientOne($globalRef)['error']['code']);
        self::assertTrue($bobClientOne($globalRef)['ok']);
    }

    public function test_admin_activity_keeps_metadata_but_hides_other_actors_rich_errors_from_operators(): void
    {
        $operator = $this->user('operator', 'all');
        $other = $this->user('operator', 'all');
        $admin = $this->user('administrator', 'all');
        $target = $this->target('admin-shared', 'wp_ai_bridge');

        $this->asOauthActor($other);
        $reference = (string) Str::uuid();
        app(ActivityRecorder::class)->record($reference, 'wordpress-ability-execute', 'failure',
            $target, 'downstream_rejected', [
                'source_error_message' => 'Other actor failed at /private/other-user.php',
            ]);

        $this->actingAs($operator)->get('/admin/activity?diagnostic_reference='.$reference)
            ->assertOk()->assertSee($reference)->assertDontSee('/private/other-user.php');
        $this->actingAs($admin)->get('/admin/activity?diagnostic_reference='.$reference)
            ->assertOk()->assertSee('/private/other-user.php');
        $this->actingAs($other)->get('/admin/activity?diagnostic_reference='.$reference)
            ->assertOk()->assertSee('/private/other-user.php');
    }

    public function test_ssh_busy_and_admission_unavailable_fail_before_dispatch_with_exact_reference(): void
    {
        $owner = $this->user('owner', 'all');
        $target = $this->target('ssh-admission-fixture', 'ssh_direct');
        $recordId = (string) $target->getKey();
        $commandKey = 'ssh-command:'.hash('sha256', $recordId);
        $fileKey = 'ssh-file:'.hash('sha256', $recordId);

        // A held lease refuses the real handler before credential lookup or SSH.
        foreach ([
            [$commandKey, fn () => app(SshCommandMcpToolHandlers::class)
                ->run($owner, $target->target_id, 'echo should-not-run')],
            [$fileKey, fn () => app(SshFileMcpToolHandlers::class)
                ->stat($owner, $target->target_id, '/tmp/no-sftp-call')],
        ] as [$key, $invoke]) {
            $lock = Cache::lock($key.':lease', 90);
            self::assertTrue($lock->get());
            try {
                $this->assertSshAdmissionError($owner, $invoke(), 'connection_busy');
            } finally {
                $lock->release();
            }
        }

        // Cache lease failure is also an independently proven pre-dispatch
        // admission rejection. The real runtime must not enter the callback.
        Cache::partialMock()
            ->shouldReceive('lock')
            ->withArgs(fn (string $key, int $ttl): bool => in_array(
                $key, [$commandKey.':lease', $fileKey.':lease'], true,
            ) && $ttl === 90)
            ->andThrow(new RuntimeException('fixture cache unavailable'));

        $this->assertSshAdmissionError($owner,
            app(SshCommandMcpToolHandlers::class)
                ->run($owner, $target->target_id, 'echo should-not-run'),
            'admission_unavailable');
        $this->assertSshAdmissionError($owner,
            app(SshFileMcpToolHandlers::class)
                ->stat($owner, $target->target_id, '/tmp/no-sftp-call'),
            'admission_unavailable');
    }

    private function assertSshAdmissionError(User $owner, array $response, string $code): void
    {
        self::assertFalse($response['ok']);
        self::assertSame($code, $response['error']['code']);
        $reference = $response['error']['diagnostic_reference'];
        self::assertTrue(Str::isUuid($reference));
        $events = app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($owner, $reference)['events'];
        self::assertCount(1, $events);
        self::assertSame($reference, $events[0]['diagnostic_reference']);
        self::assertSame('gateway_admission', $events[0]['diagnostics']['failure_origin']);
        self::assertSame('admission', $events[0]['diagnostics']['failure_stage']);
        self::assertTrue($events[0]['diagnostics']['request_not_sent']);
        self::assertTrue($events[0]['diagnostics']['retry_safe']);
    }

    private function asOauthActor(User $user, string $client = 'test-client', string $profile = 'fixture'): void
    {
        request()->attributes->set('oauth_user_id', (string) $user->getAuthIdentifier());
        request()->attributes->set('oauth_client_id', $client);
        request()->attributes->set('oauth_client_profile_key', $profile);
    }

    private function readAsOAuth(User $user, ?string $reference = null, ?string $targetId = null): array
    {
        return app(OperationDiagnosticsMcpToolHandlers::class)
            ->read($user, $reference, $targetId, 1, 'test-client', 'fixture');
    }

    private function user(string $role, string $scope): User
    {
        return User::query()->create([
            'name' => ucfirst($role), 'email' => Str::random(12).'@example.test',
            'password' => 'StrongPassword!234', 'role' => $role,
            'target_scope_mode' => $scope, 'access_enabled' => true,
        ]);
    }

    private function target(string $id, string $type): Target
    {
        return Target::query()->create([
            'target_id' => $id, 'display_name' => strtoupper($id), 'connector_type' => $type,
        ]);
    }
}
