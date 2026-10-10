<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class AdminAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_selected_operator_sees_only_authorized_sites_and_direct_url_cannot_bypass_scope(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $this->allowSite($operator, $alpha);

        $this->actingAs($operator)
            ->get('/admin/targets')
            ->assertOk()
            ->assertSee('Alpha')
            ->assertDontSee('Beta');

        $this->actingAs($operator)
            ->get(route('admin.targets.show', ['target' => $alpha->target_id], false))
            ->assertOk();

        $this->actingAs($operator)
            ->get(route('admin.targets.show', ['target' => $beta->target_id], false))
            ->assertForbidden();

        $this->actingAs($operator)
            ->put(route('admin.targets.update', ['target' => $alpha->target_id], false), [
                'display_name' => 'Changed',
                'base_url' => $alpha->base_url,
            ])
            ->assertForbidden();
    }

    public function test_per_site_denial_blocks_one_site_without_blocking_other_site_route_authorization(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, TargetScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $administrator->id,
            'target_record_id' => $alpha->id,
            'permission' => GatewayPermission::TargetsUpdate->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($administrator)
            ->put(route('admin.targets.update', ['target' => $alpha->target_id], false), [
                'display_name' => 'Alpha changed',
                'base_url' => $alpha->base_url,
            ])
            ->assertForbidden();

        $this->actingAs($administrator)
            ->put(route('admin.targets.update', ['target' => $beta->target_id], false), [
                'display_name' => 'Beta changed',
                'base_url' => $beta->base_url,
            ])
            ->assertRedirect();

        self::assertSame('Alpha', $alpha->refresh()->display_name);
    }

    public function test_disabled_user_cannot_start_a_new_admin_session(): void
    {
        $user = $this->user(GatewayRole::Administrator, TargetScopeMode::All, false);

        $this->post('/admin/login', [
            'email' => $user->email,
            'password' => 'CorrectHorse!234',
        ])
            ->assertSessionHasErrors([
                'email' => 'The provided credentials are invalid.',
            ]);

        $this->assertGuest();
    }

    public function test_disabled_user_existing_browser_session_is_terminated_for_admin_and_oauth(): void
    {
        $user = $this->user(GatewayRole::Administrator, TargetScopeMode::All);

        $this->actingAs($user)
            ->get('/admin')
            ->assertOk();

        $user->forceFill(['access_enabled' => false])->save();

        $this->actingAs($user)
            ->get('/admin')
            ->assertRedirect('/admin/login');
        $this->assertGuest();

        $this->actingAs($user)
            ->get('/oauth/authorize')
            ->assertUnauthorized()
            ->assertSee('Administrator sign-in required');
        $this->assertGuest();
    }

    public function test_selected_scope_activity_excludes_other_sites_and_gateway_global_events(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $alpha = $this->site('alpha');
        $this->site('beta');
        $this->allowSite($operator, $alpha);

        $this->activity('alpha', 'alpha-visible');
        $this->activity('beta', 'beta-hidden');
        $this->activity(null, 'gateway-hidden');

        $this->actingAs($operator)
            ->get('/admin/activity')
            ->assertOk()
            ->assertSee('alpha-visible')
            ->assertDontSee('beta-hidden')
            ->assertDontSee('gateway-hidden');
    }

    private function user(
        GatewayRole $role,
        TargetScopeMode $scope,
        bool $enabled = true,
    ): User {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'target_scope_mode' => $scope->value,
            'access_enabled' => $enabled,
        ]);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'disconnected',
        ]);
    }

    private function allowSite(User $user, Target $site): void
    {
        DB::table('user_target_access')->insert([
            'user_id' => $user->id,
            'target_record_id' => $site->id,
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function activity(?string $siteId, string $operation): void
    {
        DB::table('activity_events')->insert([
            'id' => (string) Str::ulid(),
            'correlation_id' => (string) Str::uuid(),
            'actor_type' => 'system',
            'actor_id' => null,
            'client_id_hash' => null,
            'target_id' => $siteId,
            'target_record_id' => $siteId === null ? null : Target::query()->where('target_id', $siteId)->value('id'),
            'connector_type_snapshot' => $siteId === null ? null : 'wp_ai_bridge',
            'operation' => $operation,
            'outcome' => 'success',
            'error_code' => null,
            'created_at' => now(),
        ]);
    }
}
