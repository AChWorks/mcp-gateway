<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class AdminShellPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_sidebar_groups_existing_destinations_and_marks_current_location(): void
    {
        $html = $this->actingAs($this->user(GatewayRole::Owner))
            ->get('/admin')->assertOk()->getContent();
        $xpath = $this->xpath($html);

        self::assertSame(1, (int) $xpath->evaluate('count(//a[@class="skip-link"][@href="#main-content"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//main[@id="main-content"][@tabindex="-1"])'));
        self::assertSame(3, (int) $xpath->evaluate('count(//nav[@class="admin-nav"]/section)'));
        self::assertSame(8, (int) $xpath->evaluate('count(//nav[@class="admin-nav"]//a)'));
        self::assertSame(1, (int) $xpath->evaluate('count(//nav[@class="admin-nav"]//a[@aria-current="page"])'));
        self::assertSame('Dashboard', trim($xpath->evaluate('string(//nav//a[@aria-current="page"]/span)')));
        self::assertSame(1, (int) $xpath->evaluate('count(//form[@method="post"][@action="'.route('admin.logout').'"]//input[@name="_token"])'));
        self::assertSame(0, (int) $xpath->evaluate('count(//nav[@role="menu"] | //nav//*[@role="menuitem"])'));
        self::assertStringContainsString('Operational settings', $html);
    }

    public function test_restricted_sidebar_hides_unavailable_groups_and_owner_only_settings(): void
    {
        $viewer = $this->user(GatewayRole::Viewer);
        $html = $this->actingAs($viewer)->get('/admin')->assertOk()->getContent();
        $xpath = $this->xpath($html);

        self::assertSame(0, (int) $xpath->evaluate('count(//section[@aria-labelledby="nav-access-title"])'));
        self::assertSame(0, (int) $xpath->evaluate('count(//nav//a[@href="'.route('admin.operations.index').'"])'));
        self::assertSame(0, (int) $xpath->evaluate('count(//nav//a[@href="'.route('admin.oauth-clients.index').'"])'));
        self::assertSame(4, (int) $xpath->evaluate('count(//nav[@class="admin-nav"]//a)'));

        foreach ([GatewayPermission::DashboardView, GatewayPermission::TargetsView, GatewayPermission::ActivityView] as $permission) {
            DB::table('user_permission_denials')->insert([
                'user_id' => $viewer->getKey(),
                'permission' => $permission->value,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        $html = $this->actingAs($viewer->fresh())->get('/admin/connection')->assertOk()->getContent();
        $xpath = $this->xpath($html);
        self::assertSame(0, (int) $xpath->evaluate('count(//section[@aria-labelledby="nav-workspace-title"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//nav[@class="admin-nav"]//a)'));
        self::assertSame('Connection information', trim($xpath->evaluate('string(//nav//a[@aria-current="page"]/span)')));
    }

    public function test_native_navigation_and_disclosure_are_available_before_javascript(): void
    {
        $html = $this->actingAs($this->user(GatewayRole::Owner))
            ->get('/admin/targets')->assertOk()->getContent();
        $xpath = $this->xpath($html);

        self::assertSame(1, (int) $xpath->evaluate('count(//button[@type="button"][@data-admin-nav-toggle][@hidden][@aria-controls="admin-navigation"][@aria-expanded="true"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//div[@id="admin-navigation"][not(@hidden)]//nav)'));
        self::assertSame(1, (int) $xpath->evaluate('count(//nav//a[@href="'.route('admin.targets.index').'"][@aria-current="page"])'));
        self::assertSame(0, (int) $xpath->evaluate('count(//aside//*[@onclick or @onkeydown])'));
    }

    public function test_shared_assets_are_external_deferred_and_bound_to_release_and_exact_bytes(): void
    {
        $html = $this->actingAs($this->user(GatewayRole::Owner))
            ->get('/admin')->assertOk()->getContent();
        $release = trim((string) file_get_contents(base_path('VERSION')));
        $xpath = $this->xpath($html);
        $css = 'css/admin.css?v='.$release.'-'.substr((string) hash_file('sha256', public_path('css/admin.css')), 0, 12);
        $js = 'js/admin.js?v='.$release.'-'.substr((string) hash_file('sha256', public_path('js/admin.js')), 0, 12);

        self::assertStringContainsString($css, $html);
        self::assertStringContainsString($js, $html);
        self::assertSame(1, (int) $xpath->evaluate('count(//script[@defer][contains(@src, "js/admin.js?v=")])'));
        self::assertStringNotContainsString('unsafe-eval', $html);
    }

    public function test_signed_out_page_has_no_sidebar_or_account_controls(): void
    {
        $html = $this->get('/admin/login')->assertOk()->getContent();
        $xpath = $this->xpath($html);

        self::assertSame(0, (int) $xpath->evaluate('count(//aside | //nav[@class="admin-nav"] | //button[@data-admin-nav-toggle])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//body[contains(@class, "auth-page")])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//main[@id="main-content"]//form[@action="'.route('admin.login.store').'"])'));
        self::assertStringNotContainsString('Sign out', $html);
    }

    private function xpath(string $html): \DOMXPath
    {
        $document = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        return new \DOMXPath($document);
    }

    private function user(GatewayRole $role): User
    {
        return User::query()->create([
            'name' => 'Shell fixture '.$role->value,
            'email' => 'shell-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }
}
