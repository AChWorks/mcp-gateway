<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class TargetHealthPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_dashboard_inventory_and_detail_use_stored_evidence_without_remote_fan_out(): void
    {
        Http::preventStrayRequests();
        config()->set('bridge.health.stale_after_hours', 24);

        $owner = $this->user(GatewayRole::Owner, TargetScopeMode::All);
        $healthy = $this->site('healthy', TargetConnectionState::Connected, [
            'connected_at' => now(),
            'last_success_at' => now(),
        ]);
        $this->site('stale', TargetConnectionState::Connected, [
            'connected_at' => now()->subDays(3),
            'last_success_at' => now()->subDays(3),
        ]);
        $this->site('unreachable', TargetConnectionState::Error, [
            'last_error_code' => 'network_failure',
            'last_failure_at' => now(),
            'last_failure_code' => 'network_failure',
        ]);

        $this->actingAs($owner);

        $this->get('/admin')
            ->assertOk()
            ->assertSee('Registered Targets');

        $this->get('/admin/targets')
            ->assertOk()
            ->assertSee('Connected')
            ->assertSee('Stale')
            ->assertSee('Unreachable')
            ->assertSee('Connection state');

        $this->get('/admin/activity')->assertOk();

        $this->get(route('admin.targets.show', ['target' => $healthy->target_id], false))
            ->assertOk()
            ->assertSee('Connection state')
            ->assertSee('Last tested');

        Http::assertNothingSent();
    }

    public function test_health_rendering_honors_site_scope_before_pagination_and_serialization(): void
    {
        Http::preventStrayRequests();

        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $visible = $this->site('visible', TargetConnectionState::Connected, [
            'connected_at' => now(),
            'last_success_at' => now(),
        ]);
        $this->site('hidden', TargetConnectionState::Error, [
            'last_error_code' => 'network_failure',
            'last_failure_at' => now(),
            'last_failure_code' => 'network_failure',
        ]);

        DB::table('user_target_access')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $visible->id,
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($operator)
            ->get('/admin/targets')
            ->assertOk()
            ->assertSee('Visible')
            ->assertSee('Connected')
            ->assertDontSee('Hidden')
            ->assertDontSee('network_failure');

        Http::assertNothingSent();
    }

    /** @param array<string,mixed> $evidence */
    private function site(string $siteId, TargetConnectionState $state, array $evidence): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => $state,
            ...$evidence,
        ]);
    }

    private function user(GatewayRole $role, TargetScopeMode $scope): User
    {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-health-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'target_scope_mode' => $scope->value,
            'access_enabled' => true,
        ]);
    }
}
