<?php

namespace Tests\Feature\Admin;

use App\Models\User;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

final class AdminAuthenticationTest extends TestCase
{
    use RefreshDatabase;

    public function test_guest_is_redirected_to_administrator_login(): void
    {
        $this->get('/admin')
            ->assertRedirect('/admin/login');
    }

    public function test_login_form_is_available_without_exposing_secret_values(): void
    {
        $this->get('/admin/login')
            ->assertOk()
            ->assertSee('Sign in')
            ->assertSee('autocomplete="current-password"', false)
            ->assertDontSee('value="password"', false);
    }

    public function test_valid_credentials_authenticate_and_regenerate_the_session(): void
    {
        $user = User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
        ]);

        $response = $this->withSession(['pre_login_marker' => 'keep'])
            ->post('/admin/login', [
                'email' => 'admin@example.test',
                'password' => 'CorrectHorse!234',
            ]);

        $response->assertRedirect('/admin');
        $this->assertAuthenticatedAs($user);
    }

    public function test_invalid_credentials_fail_with_a_generic_error(): void
    {
        User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
        ]);

        $this->from('/admin/login')
            ->post('/admin/login', [
                'email' => 'admin@example.test',
                'password' => 'wrong-password',
            ])
            ->assertRedirect('/admin/login')
            ->assertSessionHasErrors([
                'email' => 'The provided credentials are invalid.',
            ]);

        $this->assertGuest();
    }

    public function test_login_is_rate_limited_per_email_and_ip(): void
    {
        User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
        ]);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->post('/admin/login', [
                'email' => 'admin@example.test',
                'password' => 'wrong-password',
            ])->assertSessionHasErrors('email');
        }

        $this->post('/admin/login', [
            'email' => 'admin@example.test',
            'password' => 'wrong-password',
        ])->assertTooManyRequests();
    }

    public function test_logout_is_post_only_and_ends_the_authenticated_session(): void
    {
        $user = User::query()->create([
            'name' => 'Gateway Admin',
            'email' => 'admin@example.test',
            'password' => 'CorrectHorse!234',
        ]);

        $this->actingAs($user)
            ->post('/admin/logout')
            ->assertRedirect('/admin/login');

        $this->assertGuest();
        $this->get('/admin/logout')->assertMethodNotAllowed();
    }

    public function test_admin_state_changing_routes_keep_framework_web_security_middleware(): void
    {
        $router = app('router');
        $login = Route::getRoutes()->getByName('admin.login.store');
        $logout = Route::getRoutes()->getByName('admin.logout');

        $this->assertNotNull($login);
        $this->assertNotNull($logout);

        $loginMiddleware = $router->gatherRouteMiddleware($login);
        $logoutMiddleware = $router->gatherRouteMiddleware($logout);

        $this->assertContains(PreventRequestForgery::class, $loginMiddleware);
        $this->assertContains(PreventRequestForgery::class, $logoutMiddleware);
        $this->assertContains(Authenticate::class, $logoutMiddleware);
        $this->assertTrue(collect($loginMiddleware)->contains(
            static fn (string $middleware): bool => str_starts_with($middleware, ThrottleRequests::class.':admin-login'),
        ));
    }
}
