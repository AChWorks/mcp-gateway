<?php

namespace Tests\Feature\Migration;

use App\Domain\Targets\Target;
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
