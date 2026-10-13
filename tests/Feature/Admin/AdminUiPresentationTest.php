<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class AdminUiPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_stylesheet_is_versioned_from_release_identity(): void
    {
        $this->actingAs($this->owner())
            ->get('/admin/users/create')
            ->assertOk()
            ->assertSee(
                'css/admin.css?v='.trim((string) file_get_contents(base_path('VERSION'))).'-'
                .substr((string) hash_file('sha256', public_path('css/admin.css')), 0, 12), false,
            );
    }

    public function test_adjacent_admin_panels_use_shared_spacing_without_page_specific_card_fixes(): void
    {
        $this->actingAs($this->owner())
            ->get('/admin/oauth-clients')
            ->assertOk()
            ->assertSee('class="panel panel-wide ai-client-authorizations"', false);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertStringContainsString('--ui-panel-stack-gap: 1.25rem;', $css);
        self::assertMatchesRegularExpression(
            '/\.main-content\s*>\s*\.panel\s*\+\s*\.panel\s*\{\s*margin-block-start:\s*var\(--ui-panel-stack-gap\);\s*\}/',
            $css,
        );
        self::assertStringNotContainsString('.ai-client-authorizations {', $css);
        self::assertStringContainsString('.client-grant-revoke-form {', $css);

        $targetEditor = file_get_contents(resource_path('views/admin/targets/edit.blade.php'));
        self::assertIsString($targetEditor);
        self::assertSame(2, substr_count($targetEditor, '<section class="panel panel-wide target-enrollment"'));
    }

    public function test_shared_admin_headings_wrap_valid_long_target_names_and_tables_follow_direction(): void
    {
        $name = str_repeat('L', 160);
        Target::query()->create([
            'target_id' => 'long-heading',
            'display_name' => $name,
            'connector_type' => 'wp_ai_bridge',
        ]);
        $this->actingAs($this->owner())
            ->get('/admin/targets/long-heading')
            ->assertOk()
            ->assertSee('<h1>'.$name.'</h1>', false);

        $css = file_get_contents(public_path('css/admin.css'));
        self::assertIsString($css);
        self::assertMatchesRegularExpression(
            '/\.page-heading\s*>\s*:first-child,\s*\.section-heading\s*>\s*:first-child\s*\{\s*min-width:\s*0;\s*\}/',
            $css,
        );
        self::assertMatchesRegularExpression(
            '/h1,\s*h2\s*\{[^}]*overflow-wrap:\s*anywhere;/s',
            $css,
        );
        self::assertMatchesRegularExpression('/th,\s*td\s*\{[^}]*text-align:\s*start;/s', $css);
        self::assertMatchesRegularExpression('/\.table-action\s*\{\s*text-align:\s*end;/s', $css);
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

    public function test_target_entry_remains_neutral_and_available_connectors_have_registration_flows(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)
            ->get('/admin/targets')
            ->assertOk()
            ->assertSee('Add Target')
            ->assertDontSee('Add WordPress Target');

        $this->actingAs($owner)
            ->get('/admin/targets/create')
            ->assertOk()
            ->assertSee('WordPress (WP AI Bridge)')
            ->assertSee('Direct SSH')
            ->assertSee('value="wp_ai_bridge"', false)
            ->assertSee('value="ssh_direct"', false)
            ->assertDontSee('value="ai_server_agent"', false)
            ->assertSee('WordPress public HTTPS URL')
            ->assertSee('Trusted OpenSSH server public host key')
            ->assertSee('separate trusted channel')
            ->assertSee('Password only')
            ->assertSee('Private key only')
            ->assertDontSee('Password + private key')
            ->assertSee('name="connector_type"', false)
            ->assertSee('data-connector-panel="wp_ai_bridge"', false)
            ->assertSee('data-connector-panel="ssh_direct"', false);
    }

    public function test_user_and_group_denials_are_grouped_without_exposing_future_connectors_as_active(): void
    {
        $owner = $this->owner();

        foreach (['/admin/users/create', '/admin/target-groups/create'] as $url) {
            $this->actingAs($owner)->get($url)
                ->assertOk()
                ->assertSee('Shared Target management')
                ->assertSee('WordPress (WP AI Bridge)')
                ->assertSee('Direct SSH')
                ->assertSee('Checked = DENY')
                ->assertSee('Active')
                ->assertSee('AI Server Agent')
                ->assertSee('Paused')
                ->assertSee('View paused Agent permission identifiers (read-only)')
                ->assertDontSee('SSH settings require an authorized Owner editor');
        }

        $createUser = $this->actingAs($owner)->get('/admin/users/create')->assertOk()
            ->assertSee('Gateway administration')
            ->assertSee('Active · Owner-confirmed')
            ->assertSee('ssh_permissions_reviewed')
            ->assertSee('Owner bypasses every permission and Target restriction for recovery')
            ->assertSee('confirm_ssh_permission_changes')
            ->assertSee('value="ssh.command.run"', false)
            ->assertSee('value="ssh.file.read"', false)
            ->assertSee('value="ssh.file.write"', false);
        foreach (GatewayPermission::sshCapabilities() as $permission) {
            self::assertMatchesRegularExpression(
                '/<input[^>]*name="denied_permissions\[\]"[^>]*value="'.preg_quote($permission->value, '/').'"[^>]*checked/s',
                $createUser->getContent(),
            );
        }
        $this->actingAs($owner)->get('/admin/target-groups/create')
            ->assertSee('Active · deny-only')
            ->assertSee('confirm_ssh_group_changes')
            ->assertSee('value="ssh.command.run"', false);
        self::assertSame('gateway', GatewayPermission::SecurityManage->adminGroup());
        self::assertSame('targets', GatewayPermission::TargetsView->adminGroup());
        self::assertSame('wordpress', GatewayPermission::WordpressAbilitiesInspect->adminGroup());
        self::assertSame('ssh', GatewayPermission::SshCommandRun->adminGroup());
        self::assertSame('agent', GatewayPermission::AgentCommandRun->adminGroup());
    }

    public function test_specific_wordpress_target_hides_other_connector_permissions_but_preserves_old_denials(): void
    {
        $owner = $this->owner();
        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        $target = Target::query()->create([
            'target_id' => 'wp-demo',
            'display_name' => 'WP Demo',
            'connector_type' => 'wp_ai_bridge',
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)
            ->get('/admin/users/'.$operator->getKey().'/targets/'.$target->target_id.'/edit')
            ->assertOk()
            ->assertSee('Shared Target management')
            ->assertSee('WordPress (WP AI Bridge)')
            ->assertDontSee('Review reserved permission definitions')
            ->assertDontSee('Run SSH remote commands')
            ->assertDontSee('AI Server Agent')
            ->assertSee('name="denied_permissions[]" value="ssh.command.run"', false)
            ->assertSee('Existing restrictions for other connector types are preserved');
    }

    public function test_direct_ssh_target_user_scope_edits_show_live_deny_only_controls_not_reserved_definitions(): void
    {
        $owner = $this->owner();
        $operator = User::query()->create([
            'name' => 'SSH operator',
            'email' => 'ssh-ui-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        $target = Target::query()->create([
            'target_id' => 'ssh-ui-target', 'display_name' => 'SSH Target',
            'connector_type' => 'ssh_direct',
        ]);
        $this->actingAs($owner)->get('/admin/users/'.$operator->getKey().'/targets/'.$target->target_id.'/edit')
            ->assertOk()
            ->assertSee('Direct SSH')
            ->assertSee('Active · Target-specific denies')
            ->assertSee('value="ssh.command.run"', false)
            ->assertSee('value="ssh.file.read"', false)
            ->assertSee('value="ssh.file.write"', false)
            ->assertSee('confirm_ssh_target_changes')
            ->assertDontSee('View paused Agent permission identifiers');
    }

    public function test_group_and_user_edit_preserve_stored_future_denials_as_hidden_values(): void
    {
        $owner = $this->owner();
        $group = TargetGroup::query()->create(['name' => 'Mixed connector group']);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)->get('/admin/target-groups/'.$group->getKey().'/edit')
            ->assertOk()
            ->assertSee('value="ssh.command.run"', false)
            ->assertSee('confirm_ssh_group_changes')
            ->assertDontSee('Existing denial retained');
        $this->actingAs($owner)->get('/admin/users/'.$operator->getKey().'/edit')
            ->assertOk()
            ->assertSee('ssh.command.run')
            ->assertSee('confirm_ssh_permission_changes')
            ->assertDontSee('Existing denial retained');
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
