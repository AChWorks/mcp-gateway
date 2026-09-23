<?php

namespace Tests\Feature\Mcp;

use App\Application\Mcp\PendingGatewayToolHandlers;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteGroup;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class SiteGroupMcpAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_mcp_listing_context_catalog_and_execute_share_group_aware_authorization(): void
    {
        $operator = User::query()->create([
            'name' => 'Grouped Operator',
            'email' => 'grouped-operator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'site_scope_mode' => SiteScopeMode::Selected->value,
        ]);
        $alpha = $this->site('alpha');
        $this->site('beta');
        $group = SiteGroup::query()->create(['name' => 'MCP scope']);

        DB::table('site_group_users')->insert([
            'site_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('site_group_sites')->insert([
            'site_group_id' => $group->id,
            'site_record_id' => $alpha->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $handlers = app(PendingGatewayToolHandlers::class);
        $list = $handlers->sitesList($operator);
        self::assertTrue($list['ok']);
        self::assertSame(['alpha'], array_column($list['sites'], 'site_id'));

        self::assertTrue($handlers->siteContext($operator, 'alpha')['ok']);
        self::assertSame('site_not_found', $handlers->siteContext($operator, 'beta')['error']['code']);

        $catalog = $handlers->siteAbilitiesRead($operator, 'alpha');
        self::assertFalse($catalog['ok']);
        self::assertSame('missing_credential', $catalog['error']['code']);

        $execute = $handlers->siteAbilityExecute($operator, 'alpha', 'demo/read', []);
        self::assertFalse($execute['ok']);
        self::assertSame('missing_credential', $execute['error']['code']);

        DB::table('site_group_permission_denials')->insert([
            [
                'site_group_id' => $group->id,
                'permission' => GatewayPermission::AbilitiesInspect->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'site_group_id' => $group->id,
                'permission' => GatewayPermission::AbilitiesExecuteReadonly->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'site_group_id' => $group->id,
                'permission' => GatewayPermission::AbilitiesExecuteMutating->value,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);

        $catalogDenied = $handlers->siteAbilitiesRead($operator, 'alpha');
        self::assertFalse($catalogDenied['ok']);
        self::assertSame('site_not_found', $catalogDenied['error']['code']);

        $executeDenied = $handlers->siteAbilityExecute($operator, 'alpha', 'demo/read', []);
        self::assertFalse($executeDenied['ok']);
        self::assertSame('forbidden', $executeDenied['error']['code']);
    }

    private function site(string $siteId): Site
    {
        $base = 'https://'.$siteId.'.example.test';

        return Site::query()->create([
            'site_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => 'disconnected',
        ]);
    }
}
