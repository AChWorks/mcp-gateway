<?php

namespace Tests\Feature\Migration;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

final class GatewayV3FreshSchemaTest extends TestCase
{
    use RefreshDatabase;

    public function test_clean_v3_schema_has_all_supported_connectors_and_no_historical_site_tables(): void
    {
        foreach (['targets', 'target_credentials', 'target_groups', 'ssh_direct_target_configs',
            'wp_ai_bridge_target_configs', 'arvan_api_target_configs', 'connection_relays',
            'ssh_command_jobs', 'oauth_authorizations', 'oauth_refresh_tokens',
            'oauth_dcr_clients', 'activity_events', 'operational_settings', 'target_batches', 'target_batch_items', 'target_check_evidence'] as $table) {
            self::assertTrue(Schema::hasTable($table), $table.' missing');
        }
        foreach (['sites', 'site_credentials', 'site_groups', 'site_target_reservations'] as $retired) {
            self::assertFalse(Schema::hasTable($retired), 'v2 table still present: '.$retired);
        }
        self::assertTrue(Schema::hasColumn('target_credentials', 'authority_revision'));
        self::assertTrue(Schema::hasColumns('target_batch_items', ['effect_admitted', 'late_observation_ciphertext']));
        self::assertTrue(Schema::hasColumn('targets', 'created_by_user_id'));
        self::assertTrue(Schema::hasColumn('targets', 'last_error_check_kind'));
        self::assertTrue(Schema::hasColumn('users', 'self_created_target_access'));
        self::assertTrue(Schema::hasColumn('users', 'ai_access_enabled'));
        self::assertTrue(Schema::hasColumn('ssh_direct_target_configs', 'binding_revision'));
        self::assertTrue(Schema::hasColumn('oauth_dcr_clients', 'ever_authorized_at'));
        self::assertTrue(Schema::hasColumn('oauth_dcr_clients', 'auto_retirement_eligible'));
        self::assertTrue(Schema::hasColumn('operational_settings', 'wp_ability_input_kib'));
        self::assertTrue(Schema::hasColumn('operational_settings', 'dcr_registration_capacity'));
        $expectedMigrations = array_keys(app('migrator')->getMigrationFiles(database_path('migrations')));
        self::assertNotEmpty($expectedMigrations);
        self::assertSame($expectedMigrations, DB::table('migrations')->orderBy('migration')->pluck('migration')->all());
        self::assertTrue(Schema::hasColumns('target_check_evidence', ['target_record_id', 'kind', 'transport_revision',
            'attempt_id', 'observed_at', 'error_code', 'last_failure_at', 'last_failure_code']));
        self::assertSame(46, count(Schema::getTables()) - 1);
    }

    public function test_check_evidence_backfill_keeps_only_attributable_observations_current_and_is_restart_safe(): void
    {
        $early = '2026-10-01 10:00:00.000000';
        $late = '2026-10-01 11:00:00.000000';
        $ssh = Target::query()->create([
            'target_id' => 'legacy-ssh', 'display_name' => 'SSH', 'connector_type' => 'ssh_direct',
            'connection_state' => 'connected', 'last_tested_at' => $late,
        ]);
        $wordpress = [];
        foreach (['current', 'failed', 'historical'] as $name) {
            $base = 'https://'.$name.'.example.test';
            $target = Target::query()->create([
                'target_id' => $name, 'display_name' => $name, 'connector_type' => 'wp_ai_bridge',
                'connection_state' => 'connected',
                'last_tested_at' => match ($name) {
                    'current' => $early,
                    'failed' => $late,
                    default => null,
                },
                'last_failure_at' => $name === 'failed' ? $late : null,
                'last_failure_code' => $name === 'failed' ? 'metadata_unreachable' : null,
            ]);
            DB::table('targets')->where('id', $target->getKey())->update(['transport_revision' => 3]);
            WpAiBridgeTargetConfig::query()->create([
                'target_record_id' => $target->getKey(),
                'base_url' => $base, 'base_url_hash' => hash('sha256', $base),
                'mcp_resource_url' => $base.'/mcp', 'oauth_issuer_url' => $base,
                'oauth_authorization_url' => $base.'/authorize', 'oauth_token_url' => $base.'/token',
                'oauth_revocation_url' => $base.'/revoke',
                'metadata_checked_at' => $early, 'metadata_reachable' => true,
            ]);
            $wordpress[$name] = $target;
        }
        $migration = require database_path('migrations/0001_01_01_000010_record_target_check_evidence.php');
        $migration->up();
        $evidence = DB::table('target_check_evidence')->get()->keyBy('target_record_id');
        self::assertCount(4, $evidence);
        self::assertSame('ssh_login', $evidence[$ssh->getKey()]->kind);
        self::assertSame(0, (int) $evidence[$ssh->getKey()]->transport_revision);
        self::assertNull($evidence[$ssh->getKey()]->error_code);
        $current = $evidence[$wordpress['current']->getKey()];
        self::assertSame('wordpress_metadata', $current->kind);
        self::assertSame(3, (int) $current->transport_revision);
        self::assertNull($current->error_code);
        $failed = $evidence[$wordpress['failed']->getKey()];
        self::assertSame(3, (int) $failed->transport_revision);
        self::assertSame('metadata_unreachable', $failed->error_code);
        self::assertSame($failed->observed_at, $failed->last_failure_at);
        $historical = $evidence[$wordpress['historical']->getKey()];
        self::assertNotNull($historical->observed_at);
        self::assertNull($historical->transport_revision);
        self::assertSame(4, Target::query()->where('connection_state', 'connected')->count());

        // A repeated backfill must not replace evidence recorded after migration.
        DB::table('target_check_evidence')->where('target_record_id', $ssh->getKey())
            ->update(['error_code' => 'newer_failure']);
        $migration->up();
        self::assertSame('newer_failure', DB::table('target_check_evidence')
            ->where('target_record_id', $ssh->getKey())->value('error_code'));
        self::assertSame(4, DB::table('target_check_evidence')->count());
    }

    public function test_legacy_metadata_owned_lifecycle_error_is_attributed_without_claiming_oauth_diagnostics(): void
    {
        $checked = '2026-10-01 10:00:00.000000';
        $failed = '2026-10-01 10:00:00.100000';
        $tested = '2026-10-01 10:00:00.200000';
        $records = [];
        foreach (['metadata', 'oauth-callback', 'oauth-grant', 'unknown'] as $name) {
            $base = 'https://'.$name.'.example.test';
            $target = Target::query()->create([
                'target_id' => $name, 'display_name' => $name, 'connector_type' => 'wp_ai_bridge',
                'connection_state' => $name === 'oauth-callback' ? 'reconnect_required' : 'error',
                'last_error_code' => 'network_failure', 'last_failure_code' => 'network_failure',
                'last_failure_at' => $failed, 'last_tested_at' => $name === 'unknown' ? null : $tested,
            ]);
            WpAiBridgeTargetConfig::query()->create([
                'target_record_id' => $target->getKey(),
                'base_url' => $base, 'base_url_hash' => hash('sha256', $base),
                'mcp_resource_url' => $base.'/mcp', 'oauth_issuer_url' => $base,
                'oauth_authorization_url' => $base.'/authorize', 'oauth_token_url' => $base.'/token',
                'oauth_revocation_url' => $base.'/revoke',
                'metadata_checked_at' => $checked, 'metadata_reachable' => false,
            ]);
            $records[$name] = $target;
        }
        TargetCredential::query()->create([
            'target_record_id' => $records['oauth-grant']->getKey(),
            'connector_type' => 'wp_ai_bridge', 'purpose' => 'wordpress_oauth',
            'encrypted_payload' => 'opaque-test-only',
        ]);
        $migration = require database_path('migrations/0001_01_01_000010_record_target_check_evidence.php');
        $migration->up();
        foreach ($records as $name => $target) {
            $target->refresh();
            self::assertSame($name === 'metadata' ? 'wordpress_metadata' : null, $target->getAttribute('last_error_check_kind'));
            self::assertSame('network_failure', $target->last_error_code);
            self::assertSame($name === 'oauth-callback' ? 'reconnect_required' : 'error', $target->getRawOriginal('connection_state'));
        }
        $slot = DB::table('target_check_evidence')->where('target_record_id', $records['metadata']->getKey());
        self::assertSame('network_failure', $slot->value('error_code'));
        self::assertSame(0, (int) $slot->value('transport_revision'));

        // Do not reacquire provenance for a later lifecycle diagnostic,
        // even if the old code and timestamps still happen to match.
        DB::table('targets')->where('id', $records['metadata']->getKey())->update(['last_error_check_kind' => null]);
        $migration->up();
        self::assertNull($records['metadata']->fresh()->getAttribute('last_error_check_kind'));
        self::assertSame('network_failure', $slot->value('error_code'));
    }

    public function test_fresh_v3_seeds_required_operational_state_without_old_target_or_access_data(): void
    {
        self::assertSame(0, Target::query()->count());
        self::assertSame(0, DB::table('users')->count());
        self::assertSame(0, DB::table('oauth_authorizations')->count());
        self::assertSame(1, DB::table('activity_retention_state')->where('id', 1)->count());
        self::assertSame(1, DB::table('chatgpt_file_admission_guard')->where('id', 1)->count());
        self::assertSame(1, DB::table('wp_credential_maintenance_progress')->where('id', 1)->count());
        self::assertSame(['prune', 'reconcile'], DB::table('ssh_job_maintenance_progress')
            ->orderBy('operation')->pluck('operation')->all());
        self::assertSame((string) config('oauth.client.id'), (string) DB::table('oauth_client_profiles')
            ->where('profile_key', 'chatgpt')->value('client_id'));
        self::assertSame(0, (int) DB::table('operational_settings')->where('id', 1)->value('version'));
    }

    public function test_v3_bootstrap_rejects_an_existing_v2_or_partially_initialized_database_before_mutation(): void
    {
        Schema::create('sites', static function ($table): void {
            $table->id();
        });
        $migration = require database_path('migrations/0001_01_01_000001_create_gateway_v3_schema.php');
        try {
            $migration->up();
            self::fail('v3 migration did not reject an existing Site table.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('new, empty database', $exception->getMessage());
        } finally {
            Schema::dropIfExists('sites');
        }
        self::assertSame(0, Target::query()->count());
    }

    public function test_v3_baseline_rollback_requires_database_restore_instead_of_destructive_downgrade(): void
    {
        $migration = require database_path('migrations/0001_01_01_000001_create_gateway_v3_schema.php');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Restore a verified full database backup');
        $migration->down();
    }
}
