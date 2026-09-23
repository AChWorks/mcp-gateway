<?php

namespace Tests\Feature\Admin;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class SiteGroupMigrationTest extends TestCase
{
    use DatabaseMigrations;

    public function test_group_migration_starts_empty_without_changing_existing_direct_access(): void
    {
        /** @var Migration $migration */
        $migration = require database_path('migrations/2026_09_23_010000_add_site_groups.php');
        $migration->down();

        $now = now();
        $userId = DB::table('users')->insertGetId([
            'name' => 'Existing Operator',
            'email' => 'existing-operator@example.test',
            'password' => 'legacy-hash',
            'role' => 'operator',
            'site_scope_mode' => 'selected',
            'access_enabled' => true,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $siteId = (string) Str::ulid();
        $baseUrl = 'https://alpha.example.test';
        DB::table('sites')->insert([
            'id' => $siteId,
            'site_id' => 'alpha',
            'display_name' => 'Alpha',
            'base_url' => $baseUrl,
            'base_url_hash' => hash('sha256', $baseUrl),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $baseUrl.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $baseUrl,
            'oauth_authorization_url' => $baseUrl.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $baseUrl.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $baseUrl.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => 'disconnected',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('user_site_access')->insert([
            'user_id' => $userId,
            'site_record_id' => $siteId,
            'allowed' => true,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $migration->up();

        $this->assertDatabaseHas('user_site_access', [
            'user_id' => $userId,
            'site_record_id' => $siteId,
            'allowed' => true,
        ]);
        self::assertSame(0, DB::table('site_groups')->count());
        self::assertSame(0, DB::table('site_group_sites')->count());
        self::assertSame(0, DB::table('site_group_users')->count());
        self::assertSame(0, DB::table('site_group_permission_denials')->count());
    }
}
