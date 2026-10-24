<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Models\User;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Cache\RateLimiting\Unlimited;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Tests\TestCase;

final class AdminAbuseProtectionTest extends TestCase
{
    use RefreshDatabase;

    public function test_failed_logins_are_limited_across_rotating_ips_without_account_enumeration(): void
    {
        $user = $this->owner();

        for ($i = 1; $i <= 10; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.$i])
                ->post('/admin/login', [
                    'email' => strtoupper($user->email),
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email');
        }

        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.11'])
            ->post('/admin/login', [
                'email' => $user->email,
                'password' => 'CorrectHorse!234',
            ])->assertTooManyRequests()->assertHeader('Retry-After');

        self::assertGuest();
    }

    public function test_successful_login_clears_cross_ip_failures(): void
    {
        $user = $this->owner();

        for ($i = 1; $i <= 9; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.$i])
                ->post('/admin/login', [
                    'email' => $user->email,
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email');
        }

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.10'])
            ->post('/admin/login', [
                'email' => $user->email,
                'password' => 'CorrectHorse!234',
            ])->assertRedirect('/admin');

        $this->post('/admin/logout')->assertRedirect('/admin/login');

        for ($i = 11; $i <= 19; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.$i])
                ->post('/admin/login', [
                    'email' => $user->email,
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email');
        }

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->post('/admin/login', [
                'email' => $user->email,
                'password' => 'CorrectHorse!234',
            ])->assertRedirect('/admin');
    }

    public function test_wrong_current_password_across_sensitive_admin_actions_is_limited(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);

        for ($i = 0; $i < 3; $i++) {
            $this->post('/admin/users', ['current_password' => 'wrong-password'])
                ->assertSessionHasErrors('current_password');
        }
        for ($i = 0; $i < 2; $i++) {
            $this->delete('/admin/oauth-clients/authorizations/01ARZ3NDEKTSV4RRFFQ69G5FAV', [
                'current_password' => 'wrong-password',
            ])->assertSessionHasErrors('current_password');
        }

        $this->post('/admin/users', ['current_password' => 'CorrectHorse!234'])
            ->assertTooManyRequests()->assertHeader('Retry-After');

        self::assertSame(1, User::query()->count());
    }

    public function test_correct_current_password_resets_shared_failure_counter(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);

        for ($i = 0; $i < 4; $i++) {
            $this->post('/admin/users', ['current_password' => 'wrong-password'])
                ->assertSessionHasErrors('current_password');
        }

        // Confirmation succeeds; subsequent unrelated form validation fails.
        $this->post('/admin/users', ['current_password' => 'CorrectHorse!234'])
            ->assertSessionHasErrors('name');

        for ($i = 0; $i < 4; $i++) {
            $this->post('/admin/users', ['current_password' => 'wrong-password'])
                ->assertSessionHasErrors('current_password');
        }
        $this->post('/admin/users', ['current_password' => 'CorrectHorse!234'])
            ->assertSessionHasErrors('name');
    }

    public function test_admin_mutations_have_user_and_ip_limits_but_reads_and_logout_stay_available(): void
    {
        $owner = $this->owner();
        $definition = RateLimiter::limiter('admin-mutation');
        self::assertIsCallable($definition);

        $get = Request::create('/admin', 'GET');
        self::assertInstanceOf(Unlimited::class, $definition($get));

        $post = Request::create('/admin/users', 'POST', server: ['REMOTE_ADDR' => '192.0.2.80']);
        $post->setUserResolver(static fn () => $owner);
        $limits = $definition($post);
        self::assertIsArray($limits);
        self::assertCount(2, $limits);
        self::assertContainsOnlyInstancesOf(Limit::class, $limits);
        self::assertSame(60, $limits[0]->maxAttempts);
        self::assertSame(120, $limits[1]->maxAttempts);

        $this->actingAs($owner);
        RateLimiter::for('admin-mutation', static fn (Request $request) => $request->isMethodSafe()
            || $request->routeIs('admin.logout') ? Limit::none() : Limit::perMinute(1)->by('admin-test-mutations'));
        $this->post('/admin/users', ['current_password' => 'wrong-password'])
            ->assertSessionHasErrors('current_password');
        $this->post('/admin/users', ['current_password' => 'wrong-password'])
            ->assertTooManyRequests()->assertHeader('Retry-After');
        $this->get('/admin')->assertOk();
        $this->post('/admin/logout')->assertRedirect('/admin/login');
    }

    public function test_admin_browser_responses_are_private_unframeable_and_not_cached(): void
    {
        $login = $this->get('/admin/login')->assertOk();
        $login->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('Referrer-Policy', 'no-referrer');
        self::assertStringContainsString('no-store', (string) $login->headers->get('Cache-Control'));
        self::assertStringContainsString("frame-ancestors 'none'", (string) $login->headers->get('Content-Security-Policy'));
        self::assertStringContainsString("form-action 'self'", (string) $login->headers->get('Content-Security-Policy'));

        $this->actingAs($this->owner());
        $page = $this->get('/admin')->assertOk();
        $page->assertHeader('X-Frame-Options', 'DENY');
        self::assertStringContainsString('no-store', (string) $page->headers->get('Cache-Control'));

        $this->get('/')->assertOk()->assertHeaderMissing('X-Frame-Options');
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'ai_access_enabled' => true,
        ]);
    }
}
