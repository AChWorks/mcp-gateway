<?php

namespace Tests\Feature\Admin;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class GatewayConnectionInformationTest extends TestCase
{
    use RefreshDatabase;

    public function test_guest_cannot_view_gateway_connection_information(): void
    {
        $this->get('/admin/connection')
            ->assertRedirect('/admin/login');
    }

    public function test_authenticated_administrator_can_view_public_connection_information_without_secrets(): void
    {
        $user = User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
        ]);
        $issuer = rtrim((string) config('oauth.issuer'), '/');

        $this->actingAs($user)
            ->get('/admin/connection')
            ->assertOk()
            ->assertSee('Connection information')
            ->assertSee((string) config('oauth.resource'))
            ->assertSee($issuer.'/.well-known/oauth-protected-resource/mcp')
            ->assertSee($issuer.'/.well-known/oauth-authorization-server')
            ->assertSee('Required MCP scope')
            ->assertSee('<code>mcp</code>', false)
            ->assertDontSee('OAUTH_PRIVATE_KEY_PATH')
            ->assertDontSee('storage/app/private/oauth/private.key')
            ->assertDontSee('APP_KEY')
            ->assertDontSee('access_token')
            ->assertDontSee('refresh_token')
            ->assertDontSee('client_assertion');
    }

    public function test_dashboard_links_to_gateway_connection_information(): void
    {
        $user = User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
        ]);

        $this->actingAs($user)
            ->get('/admin')
            ->assertOk()
            ->assertSee(route('admin.connection'), false)
            ->assertSee('View connection information');
    }
}
