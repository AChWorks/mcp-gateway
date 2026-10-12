<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\TargetGroupManager;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class TargetGroupManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_and_update_group_with_denials_and_required_audit(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)->post('/admin/target-groups', [
            'name' => 'Production',
            'denied_permissions' => [GatewayPermission::WordpressAbilitiesExecuteDestructive->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $group = TargetGroup::query()->where('name', 'Production')->firstOrFail();

        $this->actingAs($owner)
            ->get('/admin/target-groups')
            ->assertOk()
            ->assertSee('Production');
        $this->actingAs($owner)
            ->get('/admin/target-groups/'.$group->id.'/edit')
            ->assertOk()
            ->assertSee('Production');

        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteDestructive->value,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'target-group-create:'.$group->id,
            'outcome' => 'success',
        ]);

        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id, [
            'name' => 'Production sites',
            'denied_permissions' => [GatewayPermission::WordpressAbilitiesExecuteMutating->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        self::assertSame('Production sites', $group->refresh()->name);
        $this->assertDatabaseMissing('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteDestructive->value,
        ]);
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
        ]);
    }

    public function test_owner_explicitly_confirms_ssh_group_denial_changes_but_cannot_grant_ssh_by_group(): void
    {
        $owner = $this->owner();
        $fields = [
            'name' => 'SSH restricted group',
            'denied_permissions' => [GatewayPermission::SshCommandRun->value],
            'current_password' => 'CorrectHorse!234',
        ];

        $this->actingAs($owner)->post('/admin/target-groups', $fields)
            ->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertSame(0, TargetGroup::query()->count());

        $this->post('/admin/target-groups', [
            ...$fields, 'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        $group = TargetGroup::query()->sole();
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);

        $this->put('/admin/target-groups/'.$group->getKey(), [
            'name' => 'SSH restricted group',
            'denied_permissions' => [],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);

        $this->put('/admin/target-groups/'.$group->getKey(), [
            'name' => 'SSH restricted group',
            'denied_permissions' => [],
            'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
            'denial_revision' => app(TargetGroupManager::class)->denialRevision($group),
        ])->assertRedirect();
        $this->assertDatabaseMissing('target_group_permission_denials', [
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);

        // Removing a group denial is never a positive permission grant.
        $operator = $this->operator();
        $target = Target::query()->create([
            'target_id' => 'ssh-target',
            'display_name' => 'SSH Target',
            'connector_type' => 'ssh_direct',
        ]);
        DB::table('user_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        self::assertFalse(app(AccessControl::class)->allows(
            $operator, GatewayPermission::SshCommandRun, $target,
        ));
    }

    public function test_wrong_password_or_non_owner_cannot_manage_site_groups(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)->post('/admin/target-groups', [
            'name' => 'Blocked',
            'current_password' => 'WrongHorse!234',
        ])->assertSessionHasErrors('current_password');
        self::assertSame(0, TargetGroup::query()->count());

        $administrator = User::query()->create([
            'name' => 'Administrator',
            'email' => 'administrator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
        $this->actingAs($administrator)->get('/admin/target-groups')->assertForbidden();
    }

    public function test_owner_can_manage_group_site_and_user_membership_and_owner_assignment_is_rejected(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');
        $group = TargetGroup::query()->create(['name' => 'Operations']);

        $this->actingAs($owner)->put(route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id,
            'target' => $site->target_id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->actingAs($owner)->put(route('admin.target-groups.users.update', [
            'targetGroup' => $group->id,
            'user' => $operator->id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $this->assertDatabaseHas('target_group_targets', [
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
        ]);
        $this->assertDatabaseHas('target_group_users', [
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'target-group-target-update:'.$group->id,
            'target_id' => 'alpha',
            'outcome' => 'success',
        ]);
        $this->assertDatabaseHas('activity_events', [
            'operation' => 'target-group-user-update:'.$group->id.':'.$operator->id,
            'outcome' => 'success',
        ]);

        $this->actingAs($owner)->put(route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id,
            'target' => $site->target_id,
        ], false), [
            'assigned' => '0',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->assertDatabaseMissing('target_group_targets', [
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
        ]);

        $this->actingAs($owner)->put(route('admin.target-groups.users.update', [
            'targetGroup' => $group->id,
            'user' => $operator->id,
        ], false), [
            'assigned' => '0',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->assertDatabaseMissing('target_group_users', [
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
        ]);

        $this->actingAs($owner)->put(route('admin.target-groups.users.update', [
            'targetGroup' => $group->id,
            'user' => $owner->id,
        ], false), [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('assigned');
        $this->assertDatabaseMissing('target_group_users', [
            'target_group_id' => $group->id,
            'user_id' => $owner->id,
        ]);
    }

    public function test_deleting_group_preserves_users_sites_and_direct_site_rules(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');
        $group = TargetGroup::query()->create(['name' => 'Disposable']);

        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->id,
            'target_record_id' => $site->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'permission' => GatewayPermission::TargetsView->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->actingAs($owner)->delete('/admin/target-groups/'.$group->id, [
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect('/admin/target-groups');

        self::assertTrue(User::query()->whereKey($operator->id)->exists());
        self::assertTrue(Target::query()->whereKey($site->id)->exists());
        $this->assertDatabaseHas('user_target_access', [
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'allowed' => false,
        ]);
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'permission' => GatewayPermission::TargetsView->value,
        ]);
        self::assertSame(0, DB::table('target_group_targets')->where('target_group_id', $group->id)->count());
        self::assertSame(0, DB::table('target_group_users')->where('target_group_id', $group->id)->count());
    }

    public function test_deleting_an_ssh_deny_group_requires_confirmation_before_implicit_grant_expansion(): void
    {
        [$owner, $operator, $target, $restricted, $alternate] = $this->overlappingSshGroups();
        $access = app(AccessControl::class);
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->actingAs($owner)->delete('/admin/target-groups/'.$restricted->id, [
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');

        self::assertNotNull($restricted->fresh());
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->delete('/admin/target-groups/'.$restricted->id, [
            'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect('/admin/target-groups');

        self::assertNull($restricted->fresh());
        self::assertNotNull($alternate->fresh());
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));
    }

    public function test_ssh_group_user_and_target_membership_changes_require_separate_confirmation(): void
    {
        [$owner, $operator, $target, $restricted] = $this->overlappingSshGroups();
        $access = app(AccessControl::class);
        $userRoute = route('admin.target-groups.users.update', [
            'targetGroup' => $restricted->id, 'user' => $operator->id,
        ], false);
        $targetRoute = route('admin.target-groups.targets.update', [
            'targetGroup' => $restricted->id, 'target' => $target->target_id,
        ], false);

        $this->actingAs($owner)->get(route('admin.target-groups.users.edit', [
            'targetGroup' => $restricted->id, 'user' => $operator->id,
        ], false))->assertOk()->assertSee('confirm_ssh_group_changes');
        $this->get(route('admin.target-groups.targets.edit', [
            'targetGroup' => $restricted->id, 'target' => $target->target_id,
        ], false))->assertOk()->assertSee('confirm_ssh_group_changes');

        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($userRoute, [
            'assigned' => '0', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($userRoute, [
            'assigned' => '0', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($userRoute, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($userRoute, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($targetRoute, [
            'assigned' => '0', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($targetRoute, [
            'assigned' => '0', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($targetRoute, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($targetRoute, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        // No-op membership should not require a new SSH grant acknowledgment.
        $this->put($targetRoute, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors();
    }

    public function test_adding_a_user_to_ssh_group_requires_confirmed_owner_scope_assignment(): void
    {
        $owner = $this->owner();
        $operator = $this->operatorWithApprovedSsh($owner);
        $target = Target::query()->create([
            'target_id' => 'group-new-ssh-target',
            'display_name' => 'Group new SSH target',
            'connector_type' => 'ssh_direct',
        ]);
        $group = TargetGroup::query()->create(['name' => 'SSH Scope Group']);
        $this->linkGroupTarget($group, $target);

        $access = app(AccessControl::class);
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));
        $url = route('admin.target-groups.users.update', [
            'targetGroup' => $group->id, 'user' => $operator->id,
        ], false);

        $this->actingAs($owner)->put($url, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($url, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));
    }

    public function test_adding_an_ssh_target_to_existing_group_requires_review_before_scope_expansion(): void
    {
        $owner = $this->owner();
        $operator = $this->operatorWithApprovedSsh($owner);
        $target = Target::query()->create([
            'target_id' => 'ssh-target-new-member',
            'display_name' => 'SSH Target pending membership',
            'connector_type' => 'ssh_direct',
        ]);
        $group = TargetGroup::query()->create(['name' => 'Selected SSH owner group']);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->id,
            'user_id' => $operator->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $url = route('admin.target-groups.targets.update', [
            'targetGroup' => $group->id, 'target' => $target->target_id,
        ], false);
        $this->actingAs($owner)->put($url, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($url, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));
    }

    public function test_group_denial_update_rechecks_actual_locked_state_even_from_stale_caller(): void
    {
        $owner = $this->owner();
        $group = TargetGroup::query()->create(['name' => 'Initially restricted']);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Model a previously opened form which was already validated before
        // the SSH denial was added: the service must inspect live locked rows.
        $this->actingAs($owner);
        try {
            app(TargetGroupManager::class)->update(
                $group, 'Stale form attempted', [], false,
            );
            self::fail('A stale form erased a newly active SSH denial.');
        } catch (\DomainException $exception) {
            self::assertSame('ssh_confirmation_required', $exception->getMessage());
        }
        self::assertSame('Initially restricted', $group->fresh()->name);
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);

        app(TargetGroupManager::class)->update(
            $group, 'Explicitly reviewed', [], true,
            app(TargetGroupManager::class)->denialRevision($group),
        );
        self::assertSame('Explicitly reviewed', $group->fresh()->name);
        $this->assertDatabaseMissing('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
    }

    public function test_stale_group_confirmation_cannot_remove_unseen_ssh_denial(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);
        $manager = app(TargetGroupManager::class);
        $group = TargetGroup::query()->create(['name' => 'Revision-bound group']);

        $oldRevision = $manager->denialRevision($group);
        $this->get('/admin/target-groups/'.$group->id.'/edit')->assertOk()
            ->assertSee('name="denial_revision"', false)
            ->assertSee($oldRevision);

        // Another Owner adds a restriction after this edit form was opened.
        $manager->update($group, 'Revision-bound group', [
            GatewayPermission::SshCommandRun->value,
        ], true, $oldRevision);

        $url = '/admin/target-groups/'.$group->id;
        $oldForm = [
            'name' => 'Old form edit', 'denied_permissions' => [],
            'denial_revision' => $oldRevision,
            'current_password' => 'CorrectHorse!234',
        ];
        $this->put($url, $oldForm)->assertSessionHasErrors('confirm_ssh_group_changes');
        $this->put($url, [
            ...$oldForm, 'confirm_ssh_group_changes' => '1',
        ])->assertSessionHasErrors('denial_revision');

        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        self::assertSame('Revision-bound group', $group->fresh()->name);

        // The fresh view uses actual current denials, not stale old() fields.
        $this->get($url.'/edit')->assertOk()
            ->assertSee($manager->denialRevision($group));

        $this->put($url, [
            ...$oldForm,
            'denial_revision' => $manager->denialRevision($group),
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseMissing('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
    }

    /** @return array{User,User,Target,TargetGroup,TargetGroup} */
    private function overlappingSshGroups(): array
    {
        $owner = $this->owner();
        $operator = $this->operatorWithApprovedSsh($owner);
        $target = Target::query()->create([
            'target_id' => 'ssh-deny-overlap',
            'display_name' => 'SSH denial overlap',
            'connector_type' => 'ssh_direct',
        ]);
        $restricted = TargetGroup::query()->create(['name' => 'Restrictive SSH Group']);
        $alternate = TargetGroup::query()->create(['name' => 'Alternate SSH Scope']);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $restricted->id,
            'permission' => GatewayPermission::SshCommandRun->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);

        foreach ([$restricted, $alternate] as $group) {
            $this->linkGroupTarget($group, $target);
            DB::table('target_group_users')->insert([
                'target_group_id' => $group->id,
                'user_id' => $operator->id,
                'created_at' => now(), 'updated_at' => now(),
            ]);
        }

        return [$owner, $operator, $target, $restricted, $alternate];
    }

    private function linkGroupTarget(TargetGroup $group, Target $target): void
    {
        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->id,
            'target_record_id' => $target->id,
            'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    private function operatorWithApprovedSsh(User $owner): User
    {
        $operator = app(UserAccessManager::class)->create([
            'name' => 'Explicit SSH operator',
            'email' => 'ssh-group-operator-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'operator', 'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);

        $this->actingAs($owner)->put('/admin/users/'.$operator->id, [
            'name' => $operator->name, 'email' => $operator->email,
            'role' => 'operator', 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'denied_permissions' => [],
            'ssh_permissions_reviewed' => '1',
            'confirm_ssh_permission_changes' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors();

        self::assertTrue(app(AccessControl::class)->allows($operator, GatewayPermission::SshCommandRun));

        return $operator;
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
        ]);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
        ]);
    }
}
