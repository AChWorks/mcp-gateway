<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class TargetGroupInventoryTest extends TestCase
{
    use RefreshDatabase;

    public function test_group_scoped_inventory_filters_before_pagination_without_n_plus_one_queries(): void
    {
        $this->seedTargets(120);
        $operator = User::query()->create([
            'name' => 'Grouped Operator',
            'email' => 'group-inventory@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
        ]);
        $group = TargetGroup::query()->create(['name' => 'First seventy']);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $siteIds = DB::table('targets')->orderBy('target_id')->limit(70)->pluck('id');
        $now = now();
        DB::table('target_group_targets')->insert($siteIds->map(static fn (mixed $id): array => [
            'target_group_id' => $group->id,
            'target_record_id' => (string) $id,
            'created_at' => $now,
            'updated_at' => $now,
        ])->all());

        $inventory = app(TargetInventory::class);

        DB::flushQueryLog();
        DB::enableQueryLog();
        $first = $inventory->adminPage($operator, 1);
        $adminQueries = DB::getQueryLog();
        DB::disableQueryLog();

        self::assertCount(50, $first['items']);
        self::assertTrue($first['has_more']);
        self::assertSame('site-00001', $first['items'][0]->target_id);
        self::assertSame('site-00050', $first['items'][49]->target_id);
        // Two bounded inventory queries plus the existing global-denial check for each scopeSites() call.
        self::assertCount(4, $adminQueries);

        $second = $inventory->adminPage($operator, 2);
        self::assertCount(20, $second['items']);
        self::assertFalse($second['has_more']);
        self::assertSame('site-00051', $second['items'][0]->target_id);
        self::assertSame('site-00070', $second['items'][19]->target_id);

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

    private function seedTargets(int $count): void
    {
        $rows = [];
        $now = now();

        for ($index = 1; $index <= $count; $index++) {
            $siteId = sprintf('site-%05d', $index);
            $rows[] = [
                'id' => (string) Str::ulid(),
                'target_id' => $siteId,
                'display_name' => sprintf('Site %05d', $index),
                'connector_type' => 'wp_ai_bridge',
                'connection_state' => 'connected',
                'last_error_code' => null,
                'last_tested_at' => null,
                'connected_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('targets')->insert($rows);
    }
}
