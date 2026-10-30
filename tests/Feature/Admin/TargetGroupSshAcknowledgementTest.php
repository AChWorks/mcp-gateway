<?php

namespace Tests\Feature\Admin;

use App\Application\Access\TargetGroupManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class TargetGroupSshAcknowledgementTest extends TestCase
{
    use RefreshDatabase;

    public function test_wordpress_target_membership_has_no_ssh_checkbox_even_in_a_group_with_ssh_impact(): void
    {
        $group = $this->group();
        $target = $this->target('wordpress-member');
        $this->addSshImpact($group, 'ssh_target');
        $this->addSshImpact($group, 'ssh_denial');
        $this->actingAs($this->user(GatewayRole::Owner));
        $edit = route('admin.target-groups.targets.edit', [
            'targetGroup' => $group->id, 'target' => $target->target_id,
        ], false);
        $update = route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id, 'target' => $target->target_id,
        ], false);

        $this->get($edit)->assertOk()
            ->assertDontSee('name="confirm_ssh_group_changes"', false)
            ->assertSee('name="current_password"', false);
        foreach (['1', '0'] as $assigned) {
            $this->put($update, ['assigned' => $assigned, 'current_password' => 'CorrectHorse!234'])
                ->assertRedirect($edit)->assertSessionHasNoErrors();
            self::assertSame($assigned === '1', app(TargetGroupManager::class)->targetIsAssigned($group, $target));
        }
    }

    public function test_wordpress_group_user_assignment_and_delete_need_password_but_no_ssh_checkbox(): void
    {
        $group = $this->group();
        $this->link($group, $this->target('wordpress-only'));
        $managed = $this->user(GatewayRole::Operator);
        $this->actingAs($this->user(GatewayRole::Owner));
        $edit = route('admin.target-groups.users.edit', [
            'targetGroup' => $group->id, 'user' => $managed->id,
        ], false);
        $update = route('admin.target-groups.users.update', [
            'targetGroup' => $group->id, 'user' => $managed->id,
        ], false);
        $groupUrl = '/admin/target-groups/'.$group->id;

        $this->get($edit)->assertOk()
            ->assertDontSee('name="confirm_ssh_group_changes"', false)
            ->assertSee('name="current_password"', false);
        $this->get($groupUrl.'/edit')->assertOk()
            ->assertSee('id="confirm_ssh_group_changes"', false) // The permission editor can change SSH denials.
            ->assertDontSee('id="confirm_ssh_group_delete"', false)
            ->assertSee('id="delete_current_password"', false);

        $this->put($update, ['assigned' => '1', 'current_password' => 'wrong'])
            ->assertSessionHasErrors('current_password');
        self::assertFalse(app(TargetGroupManager::class)->userIsAssigned($group, $managed));
        $this->put($update, ['assigned' => '1', 'current_password' => 'CorrectHorse!234'])
            ->assertRedirect($edit)->assertSessionHasNoErrors();
        self::assertTrue(app(TargetGroupManager::class)->userIsAssigned($group, $managed));
        $this->delete($groupUrl, ['current_password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin/target-groups')->assertSessionHasNoErrors();
        self::assertNull($group->fresh());
    }

    public function test_ssh_target_membership_keeps_its_acknowledgement_and_noop_semantics(): void
    {
        $group = $this->group();
        $target = $this->target('ssh-member', 'ssh_direct');
        $this->actingAs($this->user(GatewayRole::Owner));
        $edit = route('admin.target-groups.targets.edit', [
            'targetGroup' => $group->id, 'target' => $target->target_id,
        ], false);
        $update = route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id, 'target' => $target->target_id,
        ], false);

        $this->get($edit)->assertOk()->assertSee('name="confirm_ssh_group_changes"', false);
        $fields = ['assigned' => '1', 'current_password' => 'CorrectHorse!234'];
        $this->put($update, $fields)->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse(app(TargetGroupManager::class)->targetIsAssigned($group, $target));
        $this->put($update, [...$fields, 'confirm_ssh_group_changes' => '1'])
            ->assertRedirect($edit)->assertSessionHasNoErrors();
        self::assertTrue(app(TargetGroupManager::class)->targetIsAssigned($group, $target));
        $this->put($update, $fields)->assertRedirect($edit)->assertSessionHasNoErrors();
    }

    #[DataProvider('sshImpacts')]
    public function test_group_user_and_delete_acknowledgements_include_ssh_denial_only_groups(string $impact): void
    {
        $group = $this->group();
        $this->addSshImpact($group, $impact);
        $managed = $this->user(GatewayRole::Operator);
        $this->actingAs($this->user(GatewayRole::Owner));

        if ($impact === 'ssh_denial') {
            self::assertSame(0, DB::table('target_group_targets')->where('target_group_id', $group->id)->count());
        }
        self::assertTrue(app(TargetGroupManager::class)->hasSshAccessImpact($group));
        $this->get(route('admin.target-groups.users.edit', [
            'targetGroup' => $group->id, 'user' => $managed->id,
        ], false))->assertOk()->assertSee('name="confirm_ssh_group_changes"', false);
        $this->get('/admin/target-groups/'.$group->id.'/edit')->assertOk()
            ->assertSee('id="confirm_ssh_group_delete"', false);
    }

    #[DataProvider('sshImpacts')]
    public function test_a_stale_non_ssh_render_cannot_bypass_fresh_locked_membership_and_delete_review(string $impact): void
    {
        $group = $this->group();
        $managed = $this->user(GatewayRole::Operator);
        $this->actingAs($this->user(GatewayRole::Owner));
        $edit = route('admin.target-groups.users.edit', [
            'targetGroup' => $group->id, 'user' => $managed->id,
        ], false);
        $update = route('admin.target-groups.users.update', [
            'targetGroup' => $group->id, 'user' => $managed->id,
        ], false);
        $groupUrl = '/admin/target-groups/'.$group->id;
        $this->get($edit)->assertOk()->assertDontSee('name="confirm_ssh_group_changes"', false);
        $this->get($groupUrl.'/edit')->assertOk()->assertDontSee('id="confirm_ssh_group_delete"', false);

        // Model another authorized change after the Owner's form was rendered.
        $this->addSshImpact($group, $impact);
        $fields = ['assigned' => '1', 'current_password' => 'CorrectHorse!234'];
        $this->put($update, $fields)->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse(app(TargetGroupManager::class)->userIsAssigned($group, $managed));
        $this->delete($groupUrl, ['current_password' => 'CorrectHorse!234'])
            ->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertNotNull($group->fresh());

        $this->get($edit)->assertOk()->assertSee('name="confirm_ssh_group_changes"', false);
        $this->get($groupUrl.'/edit')->assertOk()->assertSee('id="confirm_ssh_group_delete"', false);
        $this->put($update, [...$fields, 'confirm_ssh_group_changes' => '1'])
            ->assertRedirect($edit)->assertSessionHasNoErrors();
        self::assertTrue(app(TargetGroupManager::class)->userIsAssigned($group, $managed));
        $this->delete($groupUrl, [
            'current_password' => 'CorrectHorse!234', 'confirm_ssh_group_changes' => '1',
        ])->assertRedirect('/admin/target-groups')->assertSessionHasNoErrors();
        self::assertNull($group->fresh());
    }

    public function test_permission_editors_keep_ssh_review_and_direct_target_editors_remain_connector_specific(): void
    {
        $owner = $this->user(GatewayRole::Owner);
        $managed = $this->user(GatewayRole::Operator);
        $group = $this->group();
        $this->actingAs($owner);
        $this->get('/admin/target-groups/create')->assertOk()
            ->assertSee('name="confirm_ssh_group_changes"', false);
        $this->get('/admin/target-groups/'.$group->id.'/edit')->assertOk()
            ->assertSee('id="confirm_ssh_group_changes"', false)
            ->assertDontSee('id="confirm_ssh_group_delete"', false);
        $this->get('/admin/users/create')->assertOk()
            ->assertSee('name="confirm_ssh_permission_changes"', false);
        $this->get('/admin/users/'.$managed->id.'/edit')->assertOk()
            ->assertSee('name="confirm_ssh_permission_changes"', false);

        foreach (['wp_ai_bridge', 'ssh_direct'] as $type) {
            $target = $this->target('direct-'.str_replace('_', '-', $type), $type);
            $response = $this->get(route('admin.users.targets.edit', [
                'user' => $managed->id, 'target' => $target->target_id,
            ], false))->assertOk();
            if ($type === 'ssh_direct') {
                $response->assertSee('name="confirm_ssh_target_changes"', false);
            } else {
                $response->assertDontSee('name="confirm_ssh_target_changes"', false);
            }
        }
    }

    /** @return array<string, array{string}> */
    public static function sshImpacts(): array
    {
        return ['SSH Target' => ['ssh_target'], 'SSH denial without a Target' => ['ssh_denial']];
    }

    private function addSshImpact(TargetGroup $group, string $impact): void
    {
        if ($impact === 'ssh_target') {
            $this->link($group, $this->target('ssh-impact-'.$group->id, 'ssh_direct'));
        } else {
            DB::table('target_group_permission_denials')->insert([
                'target_group_id' => $group->id, 'permission' => GatewayPermission::SshFileRead->value,
                'created_at' => now(), 'updated_at' => now(),
            ]);
        }
    }

    private function link(TargetGroup $group, Target $target): void
    {
        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->id, 'target_record_id' => $target->id,
            'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    private function group(): TargetGroup
    {
        return TargetGroup::query()->create(['name' => 'Contextual group '.TargetGroup::query()->count()]);
    }

    private function target(string $id, string $connector = 'wp_ai_bridge'): Target
    {
        return Target::query()->create([
            'target_id' => strtolower($id), 'display_name' => $id, 'connector_type' => $connector,
        ]);
    }

    private function user(GatewayRole $role): User
    {
        return User::query()->create([
            'name' => $role->value, 'email' => $role->value.'-'.User::query()->count().'@example.test',
            'password' => 'CorrectHorse!234', 'role' => $role,
            'target_scope_mode' => $role === GatewayRole::Owner ? TargetScopeMode::All : TargetScopeMode::Selected,
            'access_enabled' => true,
        ]);
    }
}
