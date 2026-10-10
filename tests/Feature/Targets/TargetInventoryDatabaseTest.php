<?php

namespace Tests\Feature\Targets;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-inventory')]
final class TargetInventoryDatabaseTest extends TestCase
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
        $this->seedTargets(10000);

        $columns = collect(DB::select('SHOW COLUMNS FROM targets'))->keyBy('Field');
        self::assertSame('timestamp(6)', strtolower((string) ($columns['last_tested_at']->Type ?? '')));
        self::assertSame('timestamp(6)', strtolower((string) ($columns['last_success_at']->Type ?? '')));
        self::assertSame('timestamp(6)', strtolower((string) ($columns['last_failure_at']->Type ?? '')));

        $indexes = collect(DB::select('SHOW INDEX FROM targets'))
            ->pluck('Key_name')
            ->map(static fn (mixed $name): string => (string) $name)
            ->unique()
            ->values()
            ->all();

        self::assertContains('targets_name_id_idx', $indexes);
        self::assertContains('targets_state_name_idx', $indexes);
        self::assertContains('targets_state_success_idx', $indexes);
        self::assertContains('targets_target_id_unique', $indexes);

        $plans = [
            'admin_order' => $this->explain(
                'SELECT id, target_id, display_name FROM targets ORDER BY display_name, target_id LIMIT 51',
            ),
            'admin_state_order' => $this->explain(
                "SELECT id, target_id, display_name FROM targets WHERE connection_state = 'connected' ORDER BY display_name, target_id LIMIT 51",
            ),
            'mcp_cursor' => $this->explain(
                "SELECT target_id, display_name, connector_type, connection_state FROM targets WHERE target_id > 'target-05000' ORDER BY target_id LIMIT 101",
            ),
            'single_target' => $this->explain(
                "SELECT * FROM targets WHERE target_id = 'target-05000' LIMIT 1",
            ),
            'stale_health' => $this->explain(
                "SELECT id FROM targets WHERE connection_state = 'connected' AND last_success_at < '2030-01-01 00:00:00' LIMIT 51",
            ),
        ];

        self::assertSame('targets_name_id_idx', $plans['admin_order']['key'] ?? null);
        self::assertSame('targets_state_name_idx', $plans['admin_state_order']['key'] ?? null);
        self::assertSame('targets_target_id_unique', $plans['mcp_cursor']['key'] ?? null);
        self::assertSame('targets_target_id_unique', $plans['single_target']['key'] ?? null);
        self::assertSame('targets_state_success_idx', $plans['stale_health']['key'] ?? null);

        foreach (['admin_order', 'admin_state_order', 'mcp_cursor', 'stale_health'] as $name) {
            self::assertNotSame('ALL', $plans[$name]['type'] ?? null);
            self::assertStringNotContainsString(
                'filesort',
                strtolower((string) ($plans[$name]['Extra'] ?? '')),
            );
        }

        self::assertContains($plans['single_target']['type'] ?? null, ['const', 'ref']);
    }

    /** @return array<string,mixed> */
    private function explain(string $sql): array
    {
        $row = DB::selectOne('EXPLAIN '.$sql);
        self::assertNotNull($row);

        return (array) $row;
    }

    private function seedTargets(int $count): void
    {
        $rows = [];
        $now = now();

        for ($index = 1; $index <= $count; $index++) {
            $siteId = sprintf('target-%05d', $index);

            $rows[] = [
                'id' => (string) Str::ulid(),
                'target_id' => $siteId,
                'display_name' => sprintf('Site %05d', $index),
                'connector_type' => 'wp_ai_bridge',
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
                DB::table('targets')->insert($rows);
                $rows = [];
            }
        }

        if ($rows !== []) {
            DB::table('targets')->insert($rows);
        }
    }
}
