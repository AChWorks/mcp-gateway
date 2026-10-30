<?php

namespace Tests\Feature\Admin;

use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use DOMDocument;
use DOMXPath;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\MessageBag;
use Illuminate\Support\ViewErrorBag;
use Tests\TestCase;

final class AdminPageConsistencyTest extends TestCase
{
    use RefreshDatabase;

    public function test_operations_section_links_preserve_one_complete_native_settings_form(): void
    {
        Http::preventStrayRequests();
        $html = $this->actingAs($this->owner())->get('/admin/operations')->assertOk()->getContent();
        $xpath = $this->xpath($html);

        $links = $xpath->query('//nav[@aria-label="Operational settings sections"]/a');
        self::assertNotFalse($links);
        self::assertSame(8, $links->length);
        foreach ($links as $link) {
            $id = substr($link->getAttribute('href'), 1);
            self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="'.$id.'"])'));
            self::assertSame('-1', $xpath->evaluate('string(//*[@id="'.$id.'"]/@tabindex)'));
        }

        self::assertSame(1, (int) $xpath->evaluate('count(//form[contains(@class,"operations-form")][@method="post"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//form[contains(@class,"operations-form")]//input[@name="_method"][@value="PUT"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//form[contains(@class,"operations-form")]//input[@name="version"])'));
        self::assertSame(count(OperationalSettings::allowed()), (int) $xpath->evaluate('count(//form[contains(@class,"operations-form")]//input[@type="number"])'));
        $this->assertDescriptionReferencesResolve($xpath);
        Http::assertNothingSent();
    }

    public function test_invalid_operational_value_remains_in_form_with_associated_error_and_no_setting_write(): void
    {
        $this->actingAs($this->owner())
            ->from('/admin/operations')
            ->put('/admin/operations', [
                'version' => '0',
                'values' => ['wp_response_kib' => '999999', 'wp_readonly_response_kib' => '256'],
                'current_password' => 'CorrectHorse!234',
            ])->assertRedirect('/admin/operations');

        $html = $this->get('/admin/operations')->assertOk()->getContent();
        $xpath = $this->xpath($html);
        self::assertSame(1, (int) $xpath->evaluate('count(//input[@id="setting_wp_response_kib"][@value="999999"][@aria-invalid="true"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="setting_wp_response_kib_error"][@role="alert"])'));
        self::assertStringContainsString('setting_wp_response_kib_error', $xpath->evaluate('string(//input[@id="setting_wp_response_kib"]/@aria-describedby)'));
        $this->assertDescriptionReferencesResolve($xpath);
        self::assertSame(0, DB::table('operational_setting_changes')->count());
        self::assertSame(0, (int) DB::table('operational_settings')->value('version'));
    }

    public function test_security_and_membership_forms_associate_their_visible_errors_without_losing_guards(): void
    {
        $owner = $this->owner();
        $operator = User::query()->create([
            'name' => 'Scoped operator',
            'email' => 'operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        $target = Target::query()->create([
            'target_id' => 'presentation-target',
            'display_name' => 'Presentation Target',
            'connector_type' => 'ssh_direct',
        ]);
        $group = TargetGroup::query()->create(['name' => 'Scoped group']);

        $errors = new ViewErrorBag;
        $errors->put('default', new MessageBag([
            'name' => 'Choose a name.',
            'role' => 'Choose an allowed role.',
            'target_scope_mode' => 'Review the Target scope.',
            'current_password' => 'Confirm your current password.',
            'access_rule' => 'Choose an allowed scope rule.',
            'assigned' => 'Review the membership choice.',
            'confirm_ssh_group_changes' => 'Confirm the SSH impact.',
            'confirm_ssh_target_changes' => 'Confirm the SSH impact.',
            'confirm_ssh_permission_changes' => 'Confirm the SSH impact.',
        ]));
        $this->actingAs($owner);
        // Match the JSON session representation received by ShareErrorsFromSession.
        foreach ([
            '/admin/users/create',
            '/admin/users/'.$operator->getKey().'/edit',
            '/admin/users/'.$operator->getKey().'/targets/'.$target->target_id.'/edit',
            '/admin/target-groups/create',
            '/admin/target-groups/'.$group->getKey().'/edit',
            '/admin/target-groups/'.$group->getKey().'/users/'.$operator->getKey().'/edit',
            '/admin/target-groups/'.$group->getKey().'/targets/'.$target->target_id.'/edit',
        ] as $url) {
            $html = $this->withSession(['errors' => [
                'default' => ['messages' => $errors->getBag('default')->messages(), 'format' => ':message'],
            ]])->get($url)->assertOk()->getContent();
            $xpath = $this->xpath($html);
            self::assertGreaterThan(0, (int) $xpath->evaluate('count(//main//input[@name="current_password"][@aria-invalid="true"][@autocomplete="current-password"])'), $url);
            self::assertGreaterThan(0, (int) $xpath->evaluate('count(//main//form[@method="post"]//input[@name="_token"])'), $url);
            $this->assertDescriptionReferencesResolve($xpath);
        }

        $xpath = $this->xpath($this->get('/admin/users/create')->assertOk()->getContent());
        self::assertSame('Deny '.GatewayPermission::SshCommandRun->title(), $xpath->evaluate('string(//input[@name="denied_permissions[]"][@value="'.GatewayPermission::SshCommandRun->value.'"]/@aria-label)'));
    }

    public function test_activity_distinguishes_unknown_effect_and_keeps_escaped_recorded_details(): void
    {
        $this->actingAs($this->owner());
        $items = [];
        foreach (['success', 'failure', 'unknown'] as $outcome) {
            $items[] = [
                'created_at' => '2026-10-30T04:00:00+00:00',
                'target_id' => 'presentation-target',
                'client_profile_key' => 'example-profile',
                'operation' => 'example-operation',
                'outcome' => $outcome,
                'error_code' => $outcome === 'success' ? null : 'outcome_unknown',
                'diagnostics' => $outcome === 'unknown' ? ['observed_message' => "Unconfirmed <script>example</script>\n/path/to/evidence"] : [],
                'correlation_id' => '00000000-0000-4000-8000-000000000001',
            ];
        }

        $html = view('admin.activity.index', [
            'feed' => ['items' => $items, 'page' => 1, 'has_more' => false],
            'filters' => [],
            'errors' => new ViewErrorBag,
        ])->render();
        $xpath = $this->xpath($html);
        self::assertSame(1, (int) $xpath->evaluate('count(//span[contains(@class,"badge-success")][normalize-space(.)="Succeeded"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//span[contains(@class,"badge-danger")][normalize-space(.)="Failed"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//span[contains(@class,"badge-warning")][normalize-space(.)="Unknown outcome"])'));
        self::assertStringContainsString('Check the recorded evidence before retrying.', $html);
        self::assertStringContainsString('Unconfirmed &lt;script&gt;example&lt;/script&gt;', $html);
        self::assertStringContainsString('/path/to/evidence', $html);
        self::assertStringNotContainsString('<script>example</script>', $html);
        self::assertSame(1, (int) $xpath->evaluate('count(//pre[contains(@class,"operation-result-preview")][@dir="ltr"])'));
    }

    private function assertDescriptionReferencesResolve(DOMXPath $xpath): void
    {
        $nodes = $xpath->query('//main//*[@aria-describedby]');
        self::assertNotFalse($nodes);
        foreach ($nodes as $node) {
            foreach (preg_split('/\s+/', trim($node->getAttribute('aria-describedby'))) ?: [] as $id) {
                self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="'.$id.'"])'), 'Description target must resolve once: '.$id);
            }
        }
    }

    private function xpath(string $html): DOMXPath
    {
        $dom = new DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        return new DOMXPath($dom);
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Presentation Owner',
            'email' => 'owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }
}
