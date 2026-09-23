<?php

namespace Tests\Feature\Sites;

use App\Application\Sites\SiteInventory;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteGroup;
use App\Domain\Access\SiteScopeMode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class SiteGroupInventoryTest extends TestCase
{
    use RefreshDatabase;

    public function test_group_scoped_inventory_filters_before_pagination_without_n_plus_one_queries(): void
    {
        $this->seedSites(120);
        $operator = User::query()->create([
            'name' => 'Grouped Operator',
            'email' => 'group-inventory@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'site_scope_mode' => SiteScopeMode::Selected->value,
        ]);
        $group = SiteGroup::query()->create(['name' => 'First seventy']);
        DB::table('site_group_users')->insert([
            'site_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $siteIds = DB::table('sites')->orderBy('site_id')->limit(70)->pluck('id');
        $now = now();
        DB::table('site_group_sites')->insert($siteIds->map(static fn (mixed $id): array => [
            'site_group_id' => $group->id,
            'site_record_id' => (string) $id,
            'created_at' => $now,
            'updated_at' => $now,
        ])->all());

        $inventory = app(SiteInventory::class);

        DB::flushQueryLog();
        DB::enableQueryLog();
        $first = $inventory->adminPage($operator, 1);
        $adminQueries = DB::getQueryLog();
        DB::disableQueryLog();

        self::assertCount(50, $first['items']);
        self::assertTrue($first['has_more']);
        self::assertSame('site-00001', $first['items'][0]->site_id);
        self::assertSame('site-00050', $first['items'][49]->site_id);
        // Two bounded inventory queries plus the existing global-denial check for each scopeSites() call.
        self::assertCount(4, $adminQueries);

        $second = $inventory->adminPage($operator, 2);
        self::assertCount(20, $second['items']);
        self::assertFalse($second['has_more']);
        self::assertSame('site-00051', $second['items'][0]->site_id);
        self::assertSame('site-00070', $second['items'][19]->site_id);

        DB::flushQueryLog();
        DB::enableQueryLog();
        $mcp = $inventory->mcpPage($operator, null, 100);
        $mcpQueries = DB::getQueryLog();
        DB::disableQueryLog();

        self::assertCount(70, $mcp['items']);
        self::assertFalse($mcp['has_more']);
        // One bounded inventory query plus the existing global-denial check.
        self::assertCount(2, $mcpQueries);
    }

    private function seedSites(int $count): void
    {
        $rows = [];
        $now = now();

        for ($index = 1; $index <= $count; $index++) {
            $siteId = sprintf('site-%05d', $index);
            $baseUrl = 'https://'.$siteId.'.example.test';
            $rows[] = [
                'id' => (string) Str::ulid(),
                'site_id' => $siteId,
                'display_name' => sprintf('Site %05d', $index),
                'base_url' => $baseUrl,
                'base_url_hash' => hash('sha256', $baseUrl),
                'connector_type' => 'wp_ai_bridge',
                'mcp_resource_url' => $baseUrl.'/wp-json/wp-ai-bridge/v1/mcp',
                'oauth_issuer_url' => $baseUrl,
                'oauth_authorization_url' => $baseUrl.'/wp-ai-bridge/oauth/authorize',
                'oauth_token_url' => $baseUrl.'/wp-json/wp-ai-bridge/v1/oauth/token',
                'oauth_revocation_url' => $baseUrl.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
                'connection_state' => 'connected',
                'last_error_code' => null,
                'last_tested_at' => null,
                'connected_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('sites')->insert($rows);
    }
}
