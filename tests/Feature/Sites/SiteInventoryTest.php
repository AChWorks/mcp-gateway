<?php

namespace Tests\Feature\Sites;

use App\Application\Mcp\PendingGatewayToolHandlers;
use App\Application\Sites\SiteInventory;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Tests\TestCase;

final class SiteInventoryTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_inventory_is_one_query_and_one_page_at_representative_fleet_sizes(): void
    {
        $inventory = app(SiteInventory::class);

        foreach ([[1, 100], [101, 200], [201, 500]] as [$from, $to]) {
            $this->seedSites($from, $to);

            DB::flushQueryLog();
            DB::enableQueryLog();
            $page = $inventory->adminPage();
            $queries = DB::getQueryLog();
            DB::disableQueryLog();

            self::assertCount(SiteInventory::ADMIN_PAGE_SIZE, $page['items']);
            self::assertSame(SiteInventory::ADMIN_PAGE_SIZE, $page['per_page']);
            self::assertTrue($page['has_more']);
            self::assertCount(1, $queries);
            self::assertSame('site-00001', $page['items'][0]->site_id);
            self::assertSame('site-00050', $page['items'][49]->site_id);
        }
    }

    public function test_admin_inventory_page_search_and_state_filter_are_deterministic(): void
    {
        $this->seedSites(1, 120);
        $inventory = app(SiteInventory::class);

        $secondPage = $inventory->adminPage(2);
        self::assertSame('site-00051', $secondPage['items'][0]->site_id);
        self::assertSame('site-00100', $secondPage['items'][49]->site_id);
        self::assertTrue($secondPage['has_more']);

        $filtered = $inventory->adminPage(1, 'Site 001', 'connected');
        self::assertNotSame([], $filtered['items']);
        self::assertFalse($filtered['has_more']);

        foreach ($filtered['items'] as $site) {
            self::assertStringContainsString('Site 001', $site->display_name);
            self::assertSame('connected', $site->getRawOriginal('connection_state'));
        }
    }

    public function test_admin_sites_http_page_is_bounded_and_keeps_filters_across_pagination(): void
    {
        $this->seedSites(1, 120);
        $this->actingAs(User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'inventory-admin@example.test',
            'password' => 'CorrectHorse!234',
        ]));

        $first = $this->get('/admin/sites');
        $first->assertOk()
            ->assertSee('Site 00001')
            ->assertSee('Site 00050')
            ->assertDontSee('Site 00051')
            ->assertSee('Next');

        $second = $this->get('/admin/sites?page=2');
        $second->assertOk()
            ->assertSee('Site 00051')
            ->assertSee('Site 00100')
            ->assertDontSee('Site 00050')
            ->assertSee('Previous')
            ->assertSee('Next');

        $filtered = $this->get('/admin/sites?search=Site%20001&connection_state=connected');
        $filtered->assertOk()
            ->assertSee('Site 00102')
            ->assertDontSee('Site 00101')
            ->assertSee('value="connected" selected', false);
    }

    public function test_mcp_cursor_discovers_the_entire_representative_fleet_without_unbounded_pages(): void
    {
        $this->seedSites(1, 500);
        $inventory = app(SiteInventory::class);
        $cursor = null;
        $discovered = [];
        $queries = 0;

        do {
            DB::flushQueryLog();
            DB::enableQueryLog();
            $page = $inventory->mcpPage($cursor, 73);
            $queryLog = DB::getQueryLog();
            DB::disableQueryLog();

            self::assertCount(1, $queryLog);
            self::assertLessThanOrEqual(73, count($page['items']));
            $queries += count($queryLog);

            foreach ($page['items'] as $site) {
                $discovered[] = $site->site_id;
            }

            $cursor = $page['next_cursor'];
        } while ($cursor !== null);

        self::assertCount(500, $discovered);
        self::assertCount(500, array_unique($discovered));
        self::assertSame('site-00001', $discovered[0]);
        self::assertSame('site-00500', $discovered[499]);
        self::assertSame(7, $queries);
    }

    public function test_sites_list_preserves_no_argument_first_page_and_adds_deterministic_continuation(): void
    {
        $this->seedSites(1, 150);
        $handlers = app(PendingGatewayToolHandlers::class);

        $first = $handlers->sitesList();
        self::assertTrue($first['ok']);
        self::assertCount(100, $first['sites']);
        self::assertTrue($first['truncated']);
        self::assertSame('site-00100', $first['next_cursor']);

        $second = $handlers->sitesList(cursor: $first['next_cursor']);
        self::assertTrue($second['ok']);
        self::assertCount(50, $second['sites']);
        self::assertFalse($second['truncated']);
        self::assertNull($second['next_cursor']);
        self::assertSame('site-00101', $second['sites'][0]['site_id']);
        self::assertSame('site-00150', $second['sites'][49]['site_id']);
    }

    public function test_inventory_rejects_unbounded_or_unknown_machine_filters(): void
    {
        $inventory = app(SiteInventory::class);

        try {
            $inventory->mcpPage(limit: SiteInventory::MCP_MAX_LIMIT + 1);
            self::fail('An oversized MCP inventory limit must be rejected.');
        } catch (InvalidArgumentException $exception) {
            self::assertSame('limit must be between 1 and 100.', $exception->getMessage());
        }

        $result = app(PendingGatewayToolHandlers::class)->sitesList(connection_state: 'unknown');
        self::assertFalse($result['ok']);
        self::assertSame('invalid_input', $result['error']['code']);
    }

    private function seedSites(int $from, int $to): void
    {
        $rows = [];
        $now = now();

        for ($index = $from; $index <= $to; $index++) {
            $siteId = sprintf('site-%05d', $index);
            $baseUrl = sprintf('https://site-%05d.example.test', $index);
            $state = match ($index % 3) {
                0 => 'connected',
                1 => 'disconnected',
                default => 'error',
            };

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
                'connection_state' => $state,
                'last_error_code' => $state === 'error' ? 'network_failure' : null,
                'last_tested_at' => null,
                'connected_at' => $state === 'connected' ? $now : null,
                'created_at' => $now,
                'updated_at' => $now,
            ];

            if (count($rows) === 200) {
                DB::table('sites')->insert($rows);
                $rows = [];
            }
        }

        if ($rows !== []) {
            DB::table('sites')->insert($rows);
        }
    }
}
