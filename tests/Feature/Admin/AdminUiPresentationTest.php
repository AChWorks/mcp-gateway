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
            ->assertSee('out-of-band');
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
                ->assertSee('Command and bounded SFTP tools')
                ->assertSee('AI Server Agent')
                ->assertSee('Paused')
                ->assertSee('Review reserved permission definitions');
        }

        $this->actingAs($owner)->get('/admin/users/create')
            ->assertSee('Gateway administration');
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
            ->assertSee('name="denied_permissions[]" value="ssh.command.run"', false)
            ->assertSee('Existing denial retained');
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
