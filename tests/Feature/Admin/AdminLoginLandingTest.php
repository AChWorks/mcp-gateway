<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class AdminLoginLandingTest extends TestCase
{
    use RefreshDatabase;

    #[DataProvider('roles')]
    public function test_enabled_roles_keep_their_allowed_dashboard_as_default(string $role): void
    {
        $user = $this->user(GatewayRole::from($role));
        $this->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin');
        $this->assertAuthenticatedAs($user);
        $this->get('/admin')->assertOk();
    }

    public static function roles(): array
    {
        return array_map(static fn (GatewayRole $role): array => [$role->value], GatewayRole::cases());
    }

    public function test_denied_dashboard_sign_in_lands_on_allowed_targets_without_relaxing_the_gate(): void
    {
        $user = $this->user();
        $this->deny($user, [GatewayPermission::DashboardView]);

        $this->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin/targets');
        $this->assertAuthenticatedAs($user);
        $this->get('/admin/targets')->assertOk();
        $denied = $this->get('/admin')->assertForbidden()
            ->assertSee('This page is not available to your account')
            ->assertSee('Sign out')
            ->assertSee('href="'.route('admin.targets.index').'"', false)
            ->assertDontSee('href="'.route('admin.dashboard').'"', false);
        self::assertStringContainsString('no-store', (string) $denied->headers->get('Cache-Control'));
        self::assertStringContainsString("form-action 'self'", (string) $denied->headers->get('Content-Security-Policy'));

        $this->get('/')->assertRedirect('/admin/targets');
        $this->get('/admin/login')->assertRedirect('/admin/targets');
        $this->post('/admin/logout')->assertRedirect('/admin/login');
        $this->assertGuest();
    }

    public function test_stale_forbidden_index_intention_falls_back_and_is_consumed(): void
    {
        $user = $this->user();

        $this->withSession(['url.intended' => url('/admin/users')])
            ->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin')->assertSessionMissing('url.intended');
        $this->assertAuthenticatedAs($user);
        $this->get('/admin/users')->assertForbidden()
            ->assertSee('Continue to your available administration')
            ->assertDontSee('href="'.route('admin.users.index').'"', false);
    }

    public function test_allowed_intention_keeps_its_exact_filter_query(): void
    {
        $user = $this->user();
        $intended = '/admin/targets?search=review%20set&connection_state=connected&page=2';

        $this->withSession(['url.intended' => $intended])
            ->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect($intended)->assertSessionMissing('url.intended');
    }

    public function test_resource_specific_intention_keeps_its_own_gate_and_usable_recovery(): void
    {
        $user = $this->user();
        $intended = route('admin.users.edit', ['user' => $user->id]);

        $this->withSession(['url.intended' => $intended])
            ->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect($intended);
        $this->get($intended)->assertForbidden()
            ->assertSee('This page is not available to your account')
            ->assertSee('href="'.route('admin.dashboard').'"', false)
            ->assertSee('Sign out');
    }

    public function test_fully_restricted_enabled_account_has_honest_no_access_and_native_logout(): void
    {
        $user = $this->user();
        $this->denyHumanSections($user);

        $this->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin/access');
        $this->assertAuthenticatedAs($user);
        $this->get('/admin/access')->assertOk()
            ->assertSee('No administration sections available')
            ->assertSee('You are signed in')
            ->assertSee('Sign out')
            ->assertDontSee('class="nav-link', false);
        $this->get('/admin')->assertForbidden()->assertSee('href="'.route('admin.access').'"', false);
        $this->get('/admin/login')->assertRedirect('/admin/access');
        $this->get('/')->assertRedirect('/admin/access');

        $this->post('/admin/logout')->assertRedirect('/admin/login');
        $this->assertGuest();
        $this->get('/admin/access')->assertRedirect('/admin/login');
    }

    public function test_access_page_rechecks_newly_restored_permission_instead_of_sticking_on_no_access(): void
    {
        $user = $this->user();
        $this->denyHumanSections($user);
        $this->actingAs($user)->get('/admin/access')->assertOk();

        DB::table('user_permission_denials')->where('user_id', $user->id)
            ->where('permission', GatewayPermission::TargetsView->value)->delete();

        $this->get('/admin/access')->assertRedirect('/admin/targets');
        $this->get('/admin/targets')->assertOk();
    }

    public function test_oauth_authorization_intention_keeps_full_query_for_an_account_without_admin_sections(): void
    {
        $user = $this->user();
        $this->denyHumanSections($user);
        $intended = url('/oauth/authorize').'?client_id=https%3A%2F%2Fchatgpt.com%2Foauth%2Fclient.json'
            .'&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector_platform_oauth_redirect'
            .'&state=unchanged%2Bstate&code_challenge=sample-challenge&code_challenge_method=S256';

        $this->withSession(['url.intended' => $intended])
            ->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect($intended)->assertSessionMissing('url.intended');
        $this->assertAuthenticatedAs($user);
        $this->withSession(['url.intended' => $intended])->get('/admin/login')
            ->assertRedirect($intended)->assertSessionMissing('url.intended');
    }

    public function test_disabled_account_cannot_use_the_authentication_only_access_page(): void
    {
        $user = $this->user();
        $user->forceFill(['access_enabled' => false])->save();
        $this->actingAs($user)->get('/admin/access')->assertRedirect('/admin/login');
        $this->assertGuest();
    }

    #[DataProvider('unsafeIntentions')]
    public function test_unsafe_or_unrelated_intention_does_not_replace_the_authorized_landing(string $intended): void
    {
        $user = $this->user();

        $this->withSession(['url.intended' => $intended])
            ->post('/admin/login', ['email' => $user->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin')->assertSessionMissing('url.intended');
    }

    public static function unsafeIntentions(): array
    {
        return [
            ['https://other.example.test/admin'],
            ['//other.example.test/admin'],
            ['http://user:password@localhost/admin'],
            ['http://localhost:81/admin'],
            ['/admin/logout'],
            ['/unrelated-page'],
        ];
    }

    public function test_admin_json_and_non_admin_html_forbidden_responses_keep_their_original_boundary(): void
    {
        $this->actingAs($this->user())->getJson('/admin/users')->assertForbidden()
            ->assertJsonPath('message', 'This action is unauthorized.')
            ->assertDontSee('Continue to your available administration');

        Route::get('/forbidden-fixture', static fn () => abort(403));
        $this->get('/forbidden-fixture')->assertForbidden()
            ->assertDontSee('Continue to your available administration')
            ->assertDontSee('Sign out');
    }

    /** @param list<GatewayPermission> $permissions */
    private function deny(User $user, array $permissions): void
    {
        DB::table('user_permission_denials')->insert(array_map(
            static fn (GatewayPermission $permission): array => [
                'user_id' => $user->id, 'permission' => $permission->value,
                'created_at' => now(), 'updated_at' => now(),
            ],
            $permissions,
        ));
    }

    private function denyHumanSections(User $user): void
    {
        $this->deny($user, [
            GatewayPermission::DashboardView, GatewayPermission::TargetsView,
            GatewayPermission::ActivityView, GatewayPermission::GatewayConnectionView,
        ]);
    }

    private function user(GatewayRole $role = GatewayRole::Viewer): User
    {
        return User::query()->create([
            'name' => 'Landing fixture', 'email' => 'landing@example.test',
            'password' => 'CorrectHorse!234', 'role' => $role,
            'target_scope_mode' => TargetScopeMode::All, 'access_enabled' => true,
        ]);
    }
}
