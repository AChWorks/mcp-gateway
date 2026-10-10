<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class AdminUiPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_stylesheet_is_versioned_from_release_identity(): void
    {
        $this->actingAs($this->owner())
            ->get('/admin/users/create')
            ->assertOk()
            ->assertSee('css/admin.css?v='.trim((string) file_get_contents(base_path('VERSION'))), false);
    }

    public function test_ai_client_panels_have_scoped_spacing_and_revoke_form_styles(): void
    {
        $this->actingAs($this->owner())
            ->get('/admin/oauth-clients')
            ->assertOk()
            ->assertSee('class="panel panel-wide ai-client-authorizations"', false);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString('.ai-client-authorizations {', $css);
        self::assertStringContainsString('.client-grant-revoke-form {', $css);
    }

    public function test_permission_controls_explain_title_scope_and_effective_behavior(): void
    {
        $response = $this->actingAs($this->owner())
            ->get('/admin/users/create');

        $response
            ->assertOk()
            ->assertSee('Remove Targets')
            ->assertSee('targets.remove')
            ->assertSee('Target-scoped')
            ->assertSee('effective Target scope')
            ->assertSee('not limited to Targets the user created');
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }
}
