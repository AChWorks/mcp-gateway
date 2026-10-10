<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class TargetGroupMcpAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_mcp_listing_context_catalog_and_execute_share_group_aware_authorization(): void
    {
        $operator = User::query()->create([
            'name' => 'Grouped Operator',
            'email' => 'grouped-operator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
        ]);
        $alpha = $this->site('alpha');
        $this->site('beta');
        $group = TargetGroup::query()->create(['name' => 'MCP scope']);

        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->id,
            'target_record_id' => $alpha->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $handlers = app(TargetMcpToolHandlers::class);
        $list = $handlers->targetsList($operator);
        self::assertTrue($list['ok']);
        self::assertSame(['alpha'], array_column($list['targets'], 'target_id'));

        self::assertTrue($handlers->targetContext($operator, 'alpha')['ok']);
        self::assertSame('target_not_found', $handlers->targetContext($operator, 'beta')['error']['code']);

        $catalog = app(WordpressTargetMcpToolHandlers::class)->read($operator, 'alpha');
        self::assertFalse($catalog['ok']);
        self::assertSame('missing_credential', $catalog['error']['code']);

        $execute = app(WordpressTargetMcpToolHandlers::class)->execute($operator, 'alpha', 'demo/read', []);
        self::assertFalse($execute['ok']);
        self::assertSame('missing_credential', $execute['error']['code']);

        DB::table('target_group_permission_denials')->insert([
            [
                'target_group_id' => $group->id,
                'permission' => GatewayPermission::WordpressAbilitiesInspect->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'target_group_id' => $group->id,
                'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'target_group_id' => $group->id,
                'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);

        $catalogDenied = app(WordpressTargetMcpToolHandlers::class)->read($operator, 'alpha');
        self::assertFalse($catalogDenied['ok']);
        self::assertSame('target_not_found', $catalogDenied['error']['code']);

        $executeDenied = app(WordpressTargetMcpToolHandlers::class)->execute($operator, 'alpha', 'demo/read', []);
        self::assertFalse($executeDenied['ok']);
        self::assertSame('forbidden', $executeDenied['error']['code']);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
        ]);
    }
}
