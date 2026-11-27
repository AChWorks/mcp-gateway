<?php

namespace Tests\Feature\Targets;

use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetConfig;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Tests\TestCase;

final class TargetInventoryTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_inventory_uses_two_bounded_queries_at_representative_fleet_sizes(): void
    {
        $inventory = app(TargetInventory::class);
        $user = $this->owner();

        foreach ([[1, 100], [101, 200], [201, 500]] as [$from, $to]) {
            $this->seedTargets($from, $to);

            DB::flushQueryLog();
            DB::enableQueryLog();
            $page = $inventory->adminPage($user);
            $queries = DB::getQueryLog();
            DB::disableQueryLog();

            self::assertCount(TargetInventory::ADMIN_PAGE_SIZE, $page['items']);
            self::assertSame(TargetInventory::ADMIN_PAGE_SIZE, $page['per_page']);
            self::assertTrue($page['has_more']);
            self::assertCount(2, $queries);
            self::assertSame('target-00001', $page['items'][0]->target_id);
            self::assertSame('target-00050', $page['items'][49]->target_id);
        }
    }

    public function test_admin_inventory_page_search_and_state_filter_are_deterministic(): void
    {
        $this->seedTargets(1, 120);
        $inventory = app(TargetInventory::class);
        $user = $this->owner();

        $secondPage = $inventory->adminPage($user, 2);
        self::assertSame('target-00051', $secondPage['items'][0]->target_id);
        self::assertSame('target-00100', $secondPage['items'][49]->target_id);
        self::assertTrue($secondPage['has_more']);

        $filtered = $inventory->adminPage($user, 1, 'Site 001', 'connected');
        self::assertNotSame([], $filtered['items']);
        self::assertFalse($filtered['has_more']);

        foreach ($filtered['items'] as $target) {
            self::assertStringContainsString('Site 001', $target->display_name);
            self::assertSame('connected', $target->getRawOriginal('connection_state'));
        }
    }

    public function test_admin_targets_http_page_is_bounded_and_keeps_filters_across_pagination(): void
    {
        $this->seedTargets(1, 120);
        $this->actingAs(User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'inventory-admin@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]));

        $first = $this->get('/admin/targets');
        $first->assertOk()
            ->assertSee('Site 00001')
            ->assertSee('Site 00050')
            ->assertDontSee('Site 00051')
            ->assertSee('Next');

        $second = $this->get('/admin/targets?page=2');
        $second->assertOk()
            ->assertSee('Site 00051')
            ->assertSee('Site 00100')
            ->assertDontSee('Site 00050')
            ->assertSee('Previous')
            ->assertSee('Next');

        $filtered = $this->get('/admin/targets?search=Site%20001&connection_state=connected');
        $filtered->assertOk()
            ->assertSee('Site 00102')
            ->assertDontSee('Site 00101')
            ->assertSee('value="connected" selected', false);
    }

    public function test_mcp_cursor_discovers_the_entire_representative_fleet_without_unbounded_pages(): void
    {
        $this->seedTargets(1, 500);
        $inventory = app(TargetInventory::class);
        $user = $this->owner();
        $cursor = null;
        $discovered = [];
        $queries = 0;

        do {
            DB::flushQueryLog();
            DB::enableQueryLog();
            $page = $inventory->mcpPage($user, $cursor, 73);
            $queryLog = DB::getQueryLog();
            DB::disableQueryLog();

            self::assertCount(1, $queryLog);
            self::assertLessThanOrEqual(73, count($page['items']));
            $queries += count($queryLog);

            foreach ($page['items'] as $target) {
                $discovered[] = $target->target_id;
            }

            $cursor = $page['next_cursor'];
        } while ($cursor !== null);

        self::assertCount(500, $discovered);
        self::assertCount(500, array_unique($discovered));
        self::assertSame('target-00001', $discovered[0]);
        self::assertSame('target-00500', $discovered[499]);
        self::assertSame(7, $queries);
    }

    public function test_targets_list_preserves_no_argument_first_page_and_adds_deterministic_continuation(): void
    {
        $this->seedTargets(1, 150);
        $handlers = app(TargetMcpToolHandlers::class);
        $user = $this->owner();

        $first = $handlers->targetsList($user);
        self::assertTrue($first['ok']);
        self::assertCount(100, $first['targets']);
        self::assertTrue($first['truncated']);
        self::assertSame('target-00100', $first['next_cursor']);

        $second = $handlers->targetsList($user, cursor: $first['next_cursor']);
        self::assertTrue($second['ok']);
        self::assertCount(50, $second['targets']);
        self::assertFalse($second['truncated']);
        self::assertNull($second['next_cursor']);
        self::assertSame('target-00101', $second['targets'][0]['target_id']);
        self::assertSame('target-00150', $second['targets'][49]['target_id']);
    }

    public function test_mcp_public_metadata_is_batched_only_for_the_authorized_page(): void
    {
        Http::preventStrayRequests();
        $operator = User::query()->create([
            'name' => 'Scoped metadata operator',
            'email' => 'metadata-operator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
        ]);
        $expected = [];
        for ($i = 1; $i <= 26; $i++) {
            $slug = sprintf('api-%03d', $i);
            $target = Target::query()->create([
                'target_id' => $slug, 'display_name' => $slug,
                'connector_type' => 'arvancloud', 'connection_state' => 'disconnected',
            ]);
            if ($i !== 25) {
                ArvanApiTargetConfig::query()->create([
                    'target_record_id' => $target->getKey(), 'base_url' => 'https://'.$slug.'.example.test',
                    'spec_url' => $i % 2 === 0 ? 'https://'.$slug.'.example.test/spec' : null,
                    'probe_path' => '/private-probe-path',
                ]);
            }
            if ($i !== 26) {
                DB::table('user_target_access')->insert([
                    'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
                    'allowed' => true, 'created_at' => now(), 'updated_at' => now(),
                ]);
                $expected[$slug] = $i === 25 ? null : [
                    'base_url' => 'https://'.$slug.'.example.test', 'has_openapi_spec' => $i % 2 === 0,
                ];
            }
        }
        $handler = app(TargetMcpToolHandlers::class);
        DB::flushQueryLog();
        DB::enableQueryLog();
        try {
            $page = $handler->targetsList($operator, limit: 24);
            $queries = DB::getQueryLog();
        } finally {
            DB::disableQueryLog();
        }
        self::assertTrue($page['ok']);
        self::assertCount(24, $page['targets']);
        self::assertTrue($page['truncated']);
        $metadataQueries = array_values(array_filter($queries,
            static fn (array $query): bool => str_contains($query['query'], 'arvan_api_target_configs')));
        self::assertCount(1, $metadataQueries, 'The public metadata query count must not grow per Arvan Target.');
        self::assertCount(24, $metadataQueries[0]['bindings']);
        self::assertStringNotContainsString('probe_path', $metadataQueries[0]['query']);
        foreach ($page['targets'] as $item) {
            self::assertSame($expected[$item['target_id']], $item['arvan_api']);
        }
        $last = $handler->targetsList($operator, cursor: $page['next_cursor']);
        self::assertCount(1, $last['targets']);
        self::assertSame('api-025', $last['targets'][0]['target_id']);
        self::assertArrayNotHasKey('arvan_api', $last['targets'][0]);
        self::assertFalse($last['truncated']);
        $context = $handler->targetContext($operator, 'api-002');
        self::assertSame($expected['api-002'], $context['target']['arvan_api']);
        self::assertSame('target_not_found', $handler->targetContext($operator, 'api-026')['error']['code']);
        Http::assertNothingSent();
    }

    public function test_inventory_rejects_unbounded_or_unknown_machine_filters(): void
    {
        $inventory = app(TargetInventory::class);
        $user = $this->owner();

        try {
            $inventory->mcpPage($user, limit: TargetInventory::MCP_MAX_LIMIT + 1);
            self::fail('An oversized MCP inventory limit must be rejected.');
        } catch (InvalidArgumentException $exception) {
            self::assertSame('limit must be between 1 and 100.', $exception->getMessage());
        }

        $result = app(TargetMcpToolHandlers::class)->targetsList($user, connection_state: 'unknown');
        self::assertFalse($result['ok']);
        self::assertSame('invalid_input', $result['error']['code']);
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Inventory Owner',
            'email' => 'inventory-owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
    }

    private function seedTargets(int $from, int $to): void
    {
        $rows = [];
        $now = now();

        for ($index = $from; $index <= $to; $index++) {
            $targetId = sprintf('target-%05d', $index);
            $state = match ($index % 3) {
                0 => 'connected',
                1 => 'disconnected',
                default => 'error',
            };

            $rows[] = [
                'id' => (string) Str::ulid(),
                'target_id' => $targetId,
                'display_name' => sprintf('Site %05d', $index),
                'connector_type' => 'wp_ai_bridge',
                'connection_state' => $state,
                'last_error_code' => $state === 'error' ? 'network_failure' : null,
                'last_tested_at' => null,
                'connected_at' => $state === 'connected' ? $now : null,
                'created_at' => $now,
                'updated_at' => $now,
            ];

            if (count($rows) === 200) {
                DB::table('targets')->insert($rows);
                $rows = [];
            }
        }

        if ($rows !== []) {
            DB::table('targets')->insert($rows);
        }
    }
}
