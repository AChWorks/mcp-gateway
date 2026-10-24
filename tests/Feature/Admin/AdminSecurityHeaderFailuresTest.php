<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Models\User;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use RuntimeException;
use Tests\TestCase;

final class AdminSecurityHeaderFailuresTest extends TestCase
{
    use RefreshDatabase;

    public function test_real_csrf_mismatch_is_419_with_all_admin_security_headers(): void
    {
        // Laravel normally skips CSRF in APP_ENV=testing. Force the genuine
        // CSRF middleware branch for this one request and restore test state.
        $oldEnvironment = $this->app->environment();
        $this->app['env'] = 'production';
        try {
            $response = $this->post('/admin/login', [
                'email' => 'unknown@example.test',
                'password' => 'wrong-password',
            ])->assertStatus(419);
            $this->assertAdminHeaders($response);
        } finally {
            $this->app['env'] = $oldEnvironment;
        }
    }

    public function test_admin_login_failure_validation_unauthorized_and_forbidden_have_headers(): void
    {
        $this->assertAdminHeaders($this->get('/admin/login')->assertOk());
        $this->assertAdminHeaders($this->post('/admin/login', [
            'email' => 'unknown@example.test',
            'password' => 'wrong-password',
        ])->assertSessionHasErrors('email'));
        $this->assertAdminHeaders($this->post('/admin/login', [
            'email' => 'not-an-email',
            'password' => 'wrong-password',
        ])->assertSessionHasErrors('email'));
        $this->assertAdminHeaders($this->get('/admin')->assertRedirect('/admin/login'));

        $viewer = User::query()->create([
            'name' => 'Viewer fixture',
            'email' => 'viewer@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Viewer->value,
        ]);
        $this->assertAdminHeaders($this->actingAs($viewer)
            ->get('/admin/oauth-clients')->assertForbidden());
    }

    public function test_admin_rate_limit_and_application_error_have_headers_but_oauth_is_unchanged(): void
    {
        RateLimiter::for('admin-login', static fn () => Limit::perMinute(1)->by('admin-header-fixture'));
        $this->post('/admin/login', [
            'email' => 'unknown@example.test', 'password' => 'wrong-password',
        ])->assertSessionHasErrors('email');
        $this->assertAdminHeaders($this->post('/admin/login', [
            'email' => 'unknown@example.test', 'password' => 'wrong-password',
        ])->assertTooManyRequests()->assertHeader('Retry-After'));

        // Isolated test-only route exercises the actual exception pipeline.
        Route::middleware('web')->get('/admin/__header_error_fixture', static function (): never {
            throw new RuntimeException('Isolated Admin error response fixture.');
        });
        $this->assertAdminHeaders($this->get('/admin/__header_error_fixture')->assertStatus(500));

        $this->get('/')->assertOk()->assertHeaderMissing('X-Frame-Options');
        $this->getJson('/.well-known/oauth-authorization-server')
            ->assertOk()->assertHeaderMissing('X-Frame-Options');
    }

    private function assertAdminHeaders(TestResponse $response): void
    {
        $response->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('Referrer-Policy', 'no-referrer');
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertStringContainsString("frame-ancestors 'none'", (string) $response->headers->get('Content-Security-Policy'));
        self::assertStringContainsString("form-action 'self'", (string) $response->headers->get('Content-Security-Policy'));
    }
}
