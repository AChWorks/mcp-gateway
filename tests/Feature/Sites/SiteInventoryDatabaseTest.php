<?php

namespace Tests\Feature\Sites;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-inventory')]
final class SiteInventoryDatabaseTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB or MySQL is required for inventory query-plan validation.');
        }
    }

    public function test_inventory_indexes_match_the_real_order_filter_and_lookup_access_patterns(): void
    {
        $this->seedSites(10000);

        $columns = collect(DB::select('SHOW COLUMNS FROM sites'))->keyBy('Field');
        self::assertSame('timestamp(6)', strtolower((string) ($columns['last_tested_at']->Type ?? '')));
        self::assertSame('timestamp(6)', strtolower((string) ($columns['last_success_at']->Type ?? '')));
        self::assertSame('timestamp(6)', strtolower((string) ($columns['last_failure_at']->Type ?? '')));

        $indexes = collect(DB::select('SHOW INDEX FROM sites'))
            ->pluck('Key_name')
            ->map(static fn (mixed $name): string => (string) $name)
            ->unique()
            ->values()
            ->all();

        self::assertContains('sites_display_name_site_id_index', $indexes);
        self::assertContains('sites_state_display_name_site_id_index', $indexes);
        self::assertContains('sites_state_last_success_at_index', $indexes);
        self::assertContains('sites_site_id_unique', $indexes);

        $plans = [
            'admin_order' => $this->explain(
                'SELECT id, site_id, display_name FROM sites ORDER BY display_name, site_id LIMIT 51',
            ),
            'admin_state_order' => $this->explain(
                "SELECT id, site_id, display_name FROM sites WHERE connection_state = 'connected' ORDER BY display_name, site_id LIMIT 51",
            ),
            'mcp_cursor' => $this->explain(
                "SELECT site_id, display_name, connector_type, connection_state FROM sites WHERE site_id > 'site-05000' ORDER BY site_id LIMIT 101",
            ),
            'single_site' => $this->explain(
                "SELECT * FROM sites WHERE site_id = 'site-05000' LIMIT 1",
            ),
            'stale_health' => $this->explain(
                "SELECT id FROM sites WHERE connection_state = 'connected' AND last_success_at < '2030-01-01 00:00:00' LIMIT 51",
            ),
        ];

        self::assertSame('sites_display_name_site_id_index', $plans['admin_order']['key'] ?? null);
        self::assertSame('sites_state_display_name_site_id_index', $plans['admin_state_order']['key'] ?? null);
        self::assertSame('sites_site_id_unique', $plans['mcp_cursor']['key'] ?? null);
        self::assertSame('sites_site_id_unique', $plans['single_site']['key'] ?? null);
        self::assertSame('sites_state_last_success_at_index', $plans['stale_health']['key'] ?? null);

        foreach (['admin_order', 'admin_state_order', 'mcp_cursor', 'stale_health'] as $name) {
            self::assertNotSame('ALL', $plans[$name]['type'] ?? null);
            self::assertStringNotContainsString(
                'filesort',
                strtolower((string) ($plans[$name]['Extra'] ?? '')),
            );
        }

        self::assertContains($plans['single_site']['type'] ?? null, ['const', 'ref']);
    }

    /** @return array<string,mixed> */
    private function explain(string $sql): array
    {
        $row = DB::selectOne('EXPLAIN '.$sql);
        self::assertNotNull($row);

        return (array) $row;
    }

    private function seedSites(int $count): void
    {
        $rows = [];
        $now = now();

        for ($index = 1; $index <= $count; $index++) {
            $siteId = sprintf('site-%05d', $index);
            $baseUrl = sprintf('https://site-%05d.example.test', $index);

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
                'connection_state' => $index % 2 === 0 ? 'connected' : 'disconnected',
                'last_error_code' => null,
                'last_tested_at' => null,
                'connected_at' => $index % 2 === 0 ? $now : null,
                'last_success_at' => $index % 2 === 0 ? $now : null,
                'last_failure_at' => null,
                'last_failure_code' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ];

            if (count($rows) === 500) {
                DB::table('sites')->insert($rows);
                $rows = [];
            }
        }

        if ($rows !== []) {
            DB::table('sites')->insert($rows);
        }
    }
}
