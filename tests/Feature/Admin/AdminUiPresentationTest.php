<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class AdminUiPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_stylesheet_is_versioned_from_release_identity(): void
    {
        $releaseVersion = trim((string) file_get_contents(base_path('VERSION')));

        $this->actingAs($this->owner())
            ->get('/admin/users/create')
            ->assertOk()
            ->assertSee('css/admin.css?v='.$releaseVersion, false);
    }

    public function test_permission_controls_explain_title_scope_and_effective_behavior(): void
    {
        $response = $this->actingAs($this->owner())
            ->get('/admin/users/create');

        $response
            ->assertOk()
            ->assertSee('Remove sites')
            ->assertSee('sites.remove')
            ->assertSee('Site-scoped')
            ->assertSee('effective site scope')
            ->assertSee('not limited to sites the user created');
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'site_scope_mode' => SiteScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }
}
