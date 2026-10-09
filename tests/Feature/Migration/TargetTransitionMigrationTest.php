<?php

namespace Tests\Feature\Migration;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class TargetTransitionMigrationTest extends TestCase
{
    private const MIGRATION = '2026_10_09_000000_transition_site_domain_to_targets.php';

    public function test_clean_install_migrates_to_generic_target_and_connector_owned_storage(): void
    {
        $this->migrateLegacy();
        $this->transition()->up();

        self::assertFalse(Schema::hasTable('sites'));
        self::assertFalse(Schema::hasTable('site_credentials'));
        self::assertTrue(Schema::hasTable('targets'));
        self::assertTrue(Schema::hasTable('target_credentials'));
        self::assertTrue(Schema::hasTable('wp_ai_bridge_target_configs'));
        self::assertTrue(Schema::hasTable('target_groups'));
        self::assertTrue(Schema::hasTable('target_check_operation_targets'));
        self::assertTrue(Schema::hasColumn('users', 'target_scope_mode'));
        self::assertFalse(Schema::hasColumn('users', 'site_scope_mode'));
        self::assertTrue(Schema::hasColumn('activity_events', 'target_record_id'));
        self::assertTrue(Schema::hasColumn('activity_events', 'connector_type_snapshot'));
        self::assertFalse(Schema::hasColumn('targets', 'mcp_resource_url'));
        self::assertFalse(Schema::hasColumn('targets', 'base_url_hash'));
    }

    public function test_live_target_data_must_have_explicit_reset_and_database_backup_acknowledgment_before_any_ddl(): void
    {
        $this->migrateLegacy();
        $owner = $this->createUser('owner', 'all');
        $site = $this->createLegacySite();

        DB::table('user_site_access')->insert([
            'user_id' => $owner,
            'site_record_id' => $site,
            'allowed' => true,
        ]);
        $this->seedActivity($site === '' ? null : 'old-target');

        try {
            $this->transition()->up();
            self::fail('Live Target data was reset without explicit operator authorization and a backup.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('restorable database backup', $exception->getMessage());
        }

        self::assertTrue(Schema::hasTable('sites'));
        self::assertFalse(Schema::hasTable('targets'));
        self::assertSame(1, DB::table('sites')->count());
        self::assertSame(1, DB::table('user_site_access')->count());
        self::assertSame(1, DB::table('activity_events')->count());
        self::assertTrue(Schema::hasColumn('users', 'site_scope_mode'));
    }

    public function test_approved_upgrade_preserves_gateway_identity_and_denials_but_resets_target_state(): void
    {
        $this->migrateLegacy();
        $owner = $this->createUser('owner', 'all');
        $admin = $this->createUser('administrator', 'all');
        $operator = $this->createUser('operator', 'selected');
        $viewer = $this->createUser('viewer', 'selected');
        $site = $this->createLegacySite();

        DB::table('user_permission_denials')->insert([
            ['user_id' => $admin, 'permission' => 'connections.disconnect'],
            ['user_id' => $admin, 'permission' => 'abilities.execute.destructive'],
            ['user_id' => $operator, 'permission' => 'connection.view'],
            ['user_id' => $viewer, 'permission' => 'sites.view'],
        ]);
        DB::table('user_site_access')->insert([
            'user_id' => $operator,
            'site_record_id' => $site,
            'allowed' => true,
        ]);
        DB::table('site_groups')->insert([
            'id' => (string) Str::ulid(),
            'name' => 'legacy-group',
        ]);
        $this->seedActivity('old-target');
        $this->seedActivity(null);

        $authorization = (string) Str::ulid();
        $this->seedGatewayOAuth($authorization, $owner);

        config()->set('target_transition.reset_acknowledged', 'RESET_TARGET_STATE');
        config()->set('target_transition.database_backup_verified', 'RESTORABLE_DATABASE_BACKUP_VERIFIED');
        $this->transition()->up();

        self::assertFalse(Schema::hasTable('sites'));
        self::assertTrue(Schema::hasTable('targets'));
        self::assertSame(0, DB::table('targets')->count());
        self::assertSame(0, DB::table('user_target_access')->count());
        self::assertSame(0, DB::table('target_groups')->count());

        self::assertSame(4, DB::table('users')->count());
        self::assertSame('selected', DB::table('users')->where('id', $operator)->value('target_scope_mode'));
        self::assertSame('selected', DB::table('users')->where('id', $viewer)->value('target_scope_mode'));
        self::assertSame('owner', DB::table('users')->where('id', $owner)->value('role'));

        self::assertSame(1, DB::table('activity_events')->count());
        self::assertNull(DB::table('activity_events')->first()->target_id);
        self::assertSame(1, DB::table('activity_retention_state')->count());

        // Reauthorization from ChatGPT must be a fresh grant: no old
        // Gateway-issued access/refresh token may survive the major upgrade.
        self::assertSame(0, DB::table('oauth_authorizations')->where('id', $authorization)->count());
        self::assertSame(0, DB::table('oauth_auth_codes')->count());
        self::assertSame(1, DB::table('oauth_client_profiles')->where('profile_key', 'chatgpt')->count());
        self::assertSame(0, DB::table('oauth_refresh_recoveries')->count());
        self::assertSame(0, DB::table('oauth_access_tokens')->count());
        self::assertSame(0, DB::table('oauth_refresh_tokens')->count());

        $denied = static fn (int $id): array => DB::table('user_permission_denials')
            ->where('user_id', $id)->pluck('permission')->all();

        self::assertContains('targets.disconnect', $denied($admin));
        self::assertContains('wordpress.abilities.execute.destructive', $denied($admin));
        self::assertContains('gateway.connection.view', $denied($operator));
        self::assertContains('targets.view', $denied($viewer));
        self::assertContains('agent.root_command.run', $denied($admin));
        self::assertContains('agent.command.run', $denied($operator));
        self::assertContains('agent.environment.read', $denied($viewer));
        self::assertContains('ssh.command.run', $denied($admin));
        self::assertContains('ssh.file.write', $denied($operator));
        self::assertNotContains('ssh.command.run', $denied($viewer));
        self::assertSame([], $denied($owner));
    }

    public function test_gateway_oauth_grants_alone_require_explicit_reconnection_ack_before_any_ddl(): void
    {
        $this->migrateLegacy();
        $owner = $this->createUser('owner', 'all');
        $authorization = (string) Str::ulid();
        $this->seedGatewayOAuth($authorization, $owner);

        try {
            $this->transition()->up();
            self::fail('Active Gateway OAuth grants were erased without a restorable backup and operator acknowledgment.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('restorable database backup', $exception->getMessage());
        }

        self::assertTrue(Schema::hasTable('sites'));
        self::assertFalse(Schema::hasTable('targets'));
        self::assertSame(1, DB::table('oauth_authorizations')->where('id', $authorization)->count());
        self::assertSame(1, DB::table('oauth_auth_codes')->count());
        self::assertSame(1, DB::table('oauth_access_tokens')->count());
        self::assertSame(1, DB::table('oauth_refresh_tokens')->count());
        self::assertSame(1, DB::table('oauth_refresh_recoveries')->count());
        self::assertSame(1, DB::table('users')->where('id', $owner)->count());
    }

    public function test_unknown_permission_denial_is_rejected_before_any_mutation(): void
    {
        $this->migrateLegacy();
        $user = $this->createUser('operator', 'selected');
        DB::table('user_permission_denials')->insert([
            'user_id' => $user,
            'permission' => 'unrecognized.custom.permission',
        ]);
        config()->set('target_transition.reset_acknowledged', 'RESET_TARGET_STATE');
        config()->set('target_transition.database_backup_verified', 'RESTORABLE_DATABASE_BACKUP_VERIFIED');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unknown global permission denial');
        try {
            $this->transition()->up();
        } finally {
            self::assertTrue(Schema::hasTable('sites'));
            self::assertFalse(Schema::hasTable('targets'));
            self::assertSame('unrecognized.custom.permission', DB::table('user_permission_denials')->value('permission'));
        }
    }

    public function test_duplicate_old_and_new_permission_denials_map_idempotently(): void
    {
        $this->migrateLegacy();
        $admin = $this->createUser('administrator', 'all');
        DB::table('user_permission_denials')->insert([
            ['user_id' => $admin, 'permission' => 'sites.view'],
            ['user_id' => $admin, 'permission' => 'targets.view'],
        ]);

        $this->transition()->up();

        self::assertSame(1, DB::table('user_permission_denials')
            ->where('user_id', $admin)
            ->where('permission', 'targets.view')
            ->count());
        self::assertSame(0, DB::table('user_permission_denials')
            ->where('permission', 'sites.view')
            ->count());
        self::assertContains('ssh.command.run', DB::table('user_permission_denials')
            ->where('user_id', $admin)->pluck('permission')->all());
    }

    public function test_unsupported_account_role_aborts_before_destructive_schema_changes(): void
    {
        $this->migrateLegacy();
        $user = $this->createUser('administrator', 'all');
        DB::table('users')->where('id', $user)->update(['role' => 'unknown_custom_role']);
        config()->set('target_transition.reset_acknowledged', 'RESET_TARGET_STATE');
        config()->set('target_transition.database_backup_verified', 'RESTORABLE_DATABASE_BACKUP_VERIFIED');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unrecognized Gateway role');

        try {
            $this->transition()->up();
        } finally {
            self::assertTrue(Schema::hasTable('sites'));
            self::assertFalse(Schema::hasTable('targets'));
            self::assertSame('unknown_custom_role', DB::table('users')->where('id', $user)->value('role'));
        }
    }

    private function migrateLegacy(): void
    {
        foreach (glob(database_path('migrations/*.php')) ?: [] as $file) {
            if (basename($file) === self::MIGRATION) {
                continue;
            }
            (require $file)->up();
        }
    }

    private function transition(): object
    {
        return require database_path('migrations/'.self::MIGRATION);
    }

    private function createUser(string $role, string $scope): int
    {
        return (int) DB::table('users')->insertGetId([
            'name' => $role,
            'email' => $role.'@migration.example.test',
            'password' => 'unused-test-hash',
            'role' => $role,
            'site_scope_mode' => $scope,
            'access_enabled' => true,
        ]);
    }

    private function createLegacySite(): string
    {
        $id = (string) Str::ulid();
        DB::table('sites')->insert([
            'id' => $id,
            'site_id' => 'old-target',
            'display_name' => 'Legacy WP',
            'base_url' => 'https://old.example.test',
            'base_url_hash' => hash('sha256', 'https://old.example.test'),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => 'https://old.example.test/mcp',
            'oauth_issuer_url' => 'https://old.example.test',
            'oauth_authorization_url' => 'https://old.example.test/auth',
            'oauth_token_url' => 'https://old.example.test/token',
            'oauth_revocation_url' => 'https://old.example.test/revoke',
        ]);

        return $id;
    }

    private function seedActivity(?string $siteId): void
    {
        DB::table('activity_events')->insert([
            'id' => (string) Str::ulid(),
            'correlation_id' => (string) Str::uuid(),
            'actor_type' => 'system',
            'site_id' => $siteId,
            'operation' => 'test-operation',
            'outcome' => 'success',
        ]);
    }

    private function seedGatewayOAuth(string $id, int $userId): void
    {
        $data = [
            'authorization_id' => $id,
            'client_id' => 'urn:gateway:client:test',
            'user_id' => $userId,
            'resource' => 'https://gateway.example.test/mcp',
        ];
        DB::table('oauth_authorizations')->insert([
            'id' => $id,
            'user_id' => $userId,
            'client_id' => $data['client_id'],
            'resource' => $data['resource'],
            'resource_hash' => hash('sha256', $data['resource']),
            'scopes' => '["mcp:use"]',
        ]);
        DB::table('oauth_auth_codes')->insert([
            ...$data,
            'id' => 'gateway-auth-code',
            'scopes' => '["mcp:use"]',
            'expires_at' => now()->addMinutes(5),
        ]);
        DB::table('oauth_access_tokens')->insert([
            ...$data,
            'id' => 'gateway-access',
            'scopes' => '["mcp:use"]',
            'expires_at' => now()->addHour(),
        ]);
        DB::table('oauth_refresh_tokens')->insert([
            ...$data,
            'id' => 'gateway-refresh',
            'access_token_id' => 'gateway-access',
            'expires_at' => now()->addDay(),
        ]);
        DB::table('oauth_refresh_recoveries')->insert([
            ...$data,
            'old_token_hash' => hash('sha256', 'gateway-refresh'),
            'old_refresh_token_id' => 'gateway-refresh',
            'successor_access_token_id' => 'gateway-access',
            'effective_scopes' => '["mcp:use"]',
            'response_ciphertext' => 'encrypted-test-placeholder',
            'recovery_expires_at' => now()->addHour(),
        ]);
    }
}
