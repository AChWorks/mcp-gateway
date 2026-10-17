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
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
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

    public function test_target_and_activity_view_scope_apply_to_ai_and_admin_lookup(): void
    {
        $operator = $this->user('operator', 'selected');
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
        self::assertTrue($tool->read($operator, $a)['ok']);
        $recent = $tool->read($operator, null, 'alpha');
        self::assertTrue($recent['ok']);
        self::assertSame('recent_target_errors', $recent['lookup_mode']);
        self::assertSame('alpha', $recent['target_id']);
        self::assertCount(1, $recent['events']);
        self::assertSame($a, $recent['events'][0]['diagnostic_reference']);
        $hidden = $tool->read($operator, $b);
        self::assertSame('diagnostic_unavailable', $hidden['error']['code']);
        self::assertSame($hidden, $tool->read($operator, $global));
        self::assertSame($hidden, $tool->read($operator, (string) Str::uuid()));
        self::assertSame($hidden, $tool->read($operator, 'invalid'));
        self::assertSame($hidden, $tool->read($operator, null, 'beta'));
        self::assertSame($hidden, $tool->read($operator, null, 'not-a-target'));
        self::assertSame($hidden, $tool->read($operator));
        $this->actingAs($operator)->get('/admin/activity?diagnostic_reference='.$b)
            ->assertOk()->assertSee('No activity matches these filters.');
        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::ActivityView->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        self::assertSame($hidden, $tool->read($operator, $a));
        $this->actingAs($operator)->get('/admin/activity')->assertForbidden();
    }

    public function test_direct_and_group_activity_denials_hide_error_details_from_admin_and_ai(): void
    {
        $operator = $this->user('operator', 'selected');
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
        self::assertTrue($diagnostics->read($operator, $alphaRef)['ok']);
        self::assertTrue($diagnostics->read($operator, $betaRef)['ok']);
        $unavailable = $diagnostics->read($operator, (string) Str::uuid());

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $alpha->getKey(),
            'permission' => GatewayPermission::ActivityView->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        self::assertSame($unavailable, $diagnostics->read($operator, $alphaRef));
        self::assertSame($unavailable, $diagnostics->read($operator, null, 'alpha'));
        self::assertTrue($diagnostics->read($operator, $betaRef)['ok']);
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
        self::assertTrue($diagnostics->read($operator, $alphaRef)['ok']);

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
        self::assertSame($unavailable, $diagnostics->read($operator, $betaRef));
        self::assertSame($unavailable, $diagnostics->read($operator, null, 'beta'));
        self::assertTrue($diagnostics->read($operator, $alphaRef)['ok']);
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
