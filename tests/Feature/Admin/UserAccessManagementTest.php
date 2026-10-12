<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class UserAccessManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_a_scoped_operator_with_global_narrowing(): void
    {
        $owner = $this->owner();

        $response = $this->actingAs($owner)->post('/admin/users', [
            'name' => 'Scoped Operator',
            'email' => 'OPERATOR@Example.Test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => '1',
            'denied_permissions' => [
                GatewayPermission::TargetsTest->value,
            ],
            'current_password' => 'CorrectHorse!234',
        ]);

        $user = User::query()->where('email', 'operator@example.test')->firstOrFail();

        $response->assertRedirect(route('admin.users.edit', ['user' => $user->id], false));
        self::assertSame(GatewayRole::Operator, $user->role);
        self::assertSame(TargetScopeMode::Selected, $user->target_scope_mode);
        self::assertTrue($user->access_enabled);
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id,
            'permission' => GatewayPermission::TargetsTest->value,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'user-access-create:'.$user->id,
            'outcome' => 'success',
        ]);
    }

    public function test_owner_can_create_user_with_explicitly_confirmed_subset_of_ssh_capabilities(): void
    {
        $owner = $this->owner();
        $target = Target::query()->create([
            'target_id' => 'ssh-new-user', 'display_name' => 'New SSH Target',
            'connector_type' => 'ssh_direct',
        ]);
        $payload = [
            'name' => 'SSH initial grant',
            'email' => 'ssh-initial-grant@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => '1',
            'ssh_permissions_reviewed' => '1',
            'confirm_ssh_permission_changes' => '1',
            'denied_permissions' => [
                GatewayPermission::SshCommandRun->value,
                GatewayPermission::SshFileWrite->value,
            ],
            'current_password' => 'CorrectHorse!234',
        ];
        $this->actingAs($owner)->post('/admin/users', $payload)
            ->assertRedirect()->assertSessionHasNoErrors();
        $user = User::query()->where('email', $payload['email'])->sole();
        $access = app(AccessControl::class);

        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id, 'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id, 'permission' => GatewayPermission::SshFileWrite->value,
        ]);
        $this->assertDatabaseMissing('user_permission_denials', [
            'user_id' => $user->id, 'permission' => GatewayPermission::SshFileRead->value,
        ]);
        self::assertFalse($access->allows($user, GatewayPermission::SshFileRead, $target),
            'SSH global permission without a specific selected Target must not open remote access.');

        DB::table('user_target_access')->insert([
            'user_id' => $user->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        self::assertTrue($access->allows($user, GatewayPermission::SshFileRead, $target));
        self::assertFalse($access->allows($user, GatewayPermission::SshCommandRun, $target));
        self::assertFalse($access->allows($user, GatewayPermission::SshFileWrite, $target));
    }

    public function test_user_creation_stays_ssh_default_denied_without_confirmation_or_selected_scope(): void
    {
        $owner = $this->owner();
        $base = [
            'name' => 'Needs review',
            'email' => 'needs-review@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => '1',
            'ssh_permissions_reviewed' => '1',
            // Missing all SSH deny checkboxes is a requested all-tools grant.
            'current_password' => 'CorrectHorse!234',
        ];
        $this->actingAs($owner)->post('/admin/users', $base)
            ->assertSessionHasErrors('confirm_ssh_permission_changes');
        $this->assertDatabaseMissing('users', ['email' => $base['email']]);

        $this->post('/admin/users', [
            ...$base, 'target_scope_mode' => TargetScopeMode::All->value,
            'confirm_ssh_permission_changes' => '1',
        ])->assertSessionHasErrors('target_scope_mode');
        $this->assertDatabaseMissing('users', ['email' => $base['email']]);

        // Existing non-HTML/API callers keep the mandatory deny defaults even
        // when they do not send the newly introduced review marker.
        $this->post('/admin/users', [
            ...$base,
            'ssh_permissions_reviewed' => null,
            // An old form is not a grant-capable form, even if it submits
            // the standalone confirmation flag and omits all SSH denials.
            'confirm_ssh_permission_changes' => '1',
        ])->assertRedirect()->assertSessionHasNoErrors();
        $newUser = User::query()->where('email', $base['email'])->sole();
        foreach (GatewayPermission::sshCapabilities() as $permission) {
            $this->assertDatabaseHas('user_permission_denials', [
                'user_id' => $newUser->getKey(), 'permission' => $permission->value,
            ]);
        }
    }

    public function test_existing_ssh_grantee_can_switch_to_all_scope_while_ssh_is_revoked_automatically(): void
    {
        $owner = $this->owner();
        $user = app(UserAccessManager::class)->create([
            'name' => 'Scoped SSH grantee',
            'email' => 'scoped-ssh-grantee@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        app(UserAccessManager::class)->update($user, [
            'name' => $user->name,
            'email' => $user->email,
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], [GatewayPermission::SshFileWrite->value], true);

        $this->actingAs($owner)->put('/admin/users/'.$user->getKey(), [
            'name' => $user->name,
            'email' => $user->email,
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => '1',
            'ssh_permissions_reviewed' => '1',
            'denied_permissions' => [GatewayPermission::SshFileWrite->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors()
            ->assertSessionHas('status', 'User access updated. All Target scope disables all non-Owner SSH command and SFTP grants.');

        self::assertSame(TargetScopeMode::All, $user->fresh()->target_scope_mode);
        foreach (GatewayPermission::sshCapabilities() as $permission) {
            $this->assertDatabaseHas('user_permission_denials', [
                'user_id' => $user->getKey(), 'permission' => $permission->value,
            ]);
        }
    }

    public function test_role_promotion_cannot_enable_ssh_without_explicit_owner_review(): void
    {
        $owner = $this->owner();
        $viewer = app(UserAccessManager::class)->create([
            'name' => 'Viewer pending promotion',
            'email' => 'viewer-promotion@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'viewer',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        $request = [
            'name' => $viewer->name,
            'email' => $viewer->email,
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => '1',
            'current_password' => 'CorrectHorse!234',
            'ssh_permissions_reviewed' => '1',
            // Previously unavailable boxes on Viewer are unchecked.
        ];
        $this->actingAs($owner)->put('/admin/users/'.$viewer->id, $request)
            ->assertSessionHasErrors('confirm_ssh_permission_changes');
        self::assertSame(GatewayRole::Viewer, $viewer->fresh()->role);

        $this->put('/admin/users/'.$viewer->id, [
            ...$request,
            'confirm_ssh_permission_changes' => '1',
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertSame(GatewayRole::Operator, $viewer->fresh()->role);
        foreach (GatewayPermission::sshCapabilities() as $permission) {
            $this->assertDatabaseMissing('user_permission_denials', [
                'user_id' => $viewer->id, 'permission' => $permission->value,
            ]);
        }
    }

    public function test_owner_confirmed_ssh_target_rule_controls_reachability_and_independent_denials(): void
    {
        $owner = $this->owner();
        $operator = app(UserAccessManager::class)->create([
            'name' => 'Target rule user',
            'email' => 'target-rule-ssh@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        app(UserAccessManager::class)->update($operator, [
            'name' => $operator->name,
            'email' => $operator->email,
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], [GatewayPermission::SshCommandRun->value, GatewayPermission::SshFileWrite->value], true);
        $target = Target::query()->create([
            'target_id' => 'ssh-target-rule', 'display_name' => 'SSH Target Rule',
            'connector_type' => 'ssh_direct',
        ]);
        $access = app(AccessControl::class);
        $url = '/admin/users/'.$operator->id.'/targets/'.$target->target_id;
        $ruleManager = app(UserAccessManager::class);
        $this->actingAs($owner);
        $this->put($url, [
            'access_rule' => 'allow', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_target_changes');
        self::assertFalse($access->allows($operator, GatewayPermission::SshFileRead, $target));

        $this->put($url, [
            'access_rule' => 'allow', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_target_changes' => '1',
            'target_revision' => $ruleManager->targetRuleRevision($operator, $target),
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertTrue($access->allows($operator, GatewayPermission::SshFileRead, $target));

        $this->put($url, [
            'access_rule' => 'allow', 'current_password' => 'CorrectHorse!234',
            'denied_permissions' => [GatewayPermission::SshFileRead->value],
        ])->assertSessionHasErrors('confirm_ssh_target_changes');
        self::assertTrue($access->allows($operator, GatewayPermission::SshFileRead, $target));

        $this->put($url, [
            'access_rule' => 'allow', 'current_password' => 'CorrectHorse!234',
            'denied_permissions' => [GatewayPermission::SshFileRead->value],
            'confirm_ssh_target_changes' => '1',
            'target_revision' => $ruleManager->targetRuleRevision($operator, $target),
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertFalse($access->allows($operator, GatewayPermission::SshFileRead, $target));

        $this->put($url, [
            'access_rule' => 'allow', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_target_changes');

        $this->put($url, [
            'access_rule' => 'allow', 'current_password' => 'CorrectHorse!234',
            'confirm_ssh_target_changes' => '1',
            'target_revision' => $ruleManager->targetRuleRevision($operator, $target),
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertTrue($access->allows($operator, GatewayPermission::SshFileRead, $target));
    }

    public function test_ssh_grant_requires_separate_explicit_owner_confirmation_and_selected_scope(): void
    {
        $owner = $this->owner();
        $operator = app(UserAccessManager::class)->create([
            'name' => 'SSH operator',
            'email' => 'ssh-operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        $ssh = Target::query()->create([
            'target_id' => 'ssh-grant-target',
            'display_name' => 'SSH grant Target',
            'connector_type' => 'ssh_direct',
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $ssh->getKey(),
            'allowed' => true,
        ]);

        $access = app(AccessControl::class);
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $ssh));
        $payload = [
            'name' => $operator->name,
            'email' => $operator->email,
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'current_password' => 'CorrectHorse!234',
            // Missing deny checkboxes alone cannot silently grant SSH command.
        ];
        $this->actingAs($owner)->put('/admin/users/'.$operator->id, $payload)->assertRedirect();
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $ssh));

        // A legacy/unreviewed form cannot use an isolated confirmation flag
        // to lift existing default SSH denials.
        $this->put('/admin/users/'.$operator->id, [
            ...$payload,
            'confirm_ssh_permission_changes' => '1',
            'denied_permissions' => [],
        ])->assertRedirect();
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $ssh));
        self::assertFalse($access->allows($operator, GatewayPermission::SshFileRead, $ssh));
        self::assertFalse($access->allows($operator, GatewayPermission::SshFileWrite, $ssh));

        $this->put('/admin/users/'.$operator->id, [
            ...$payload,
            'ssh_permissions_reviewed' => '1',
            'confirm_ssh_permission_changes' => '1',
            // All three SSH tools are visible: this explicitly grants each
            // capability on the selected Target.
            'denied_permissions' => [],
        ])->assertRedirect();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $ssh));
        self::assertTrue($access->allows($operator, GatewayPermission::SshFileRead, $ssh));
        self::assertTrue($access->allows($operator, GatewayPermission::SshFileWrite, $ssh));

        // An explicit Owner edit can restrict only write without restricting read.
        $this->put('/admin/users/'.$operator->id, [
            ...$payload,
            'ssh_permissions_reviewed' => '1',
            'confirm_ssh_permission_changes' => '1',
            'denied_permissions' => [GatewayPermission::SshFileWrite->value],
        ])->assertRedirect();
        self::assertTrue($access->allows($operator, GatewayPermission::SshFileRead, $ssh));
        self::assertFalse($access->allows($operator, GatewayPermission::SshFileWrite, $ssh));

        // Broadening to all-target scope must not preserve shell privileges.
        $this->put('/admin/users/'.$operator->id, [
            ...$payload,
            'target_scope_mode' => 'all',
            'confirm_ssh_permission_changes' => '1',
        ])->assertRedirect();
        self::assertFalse($access->allows($operator->refresh(), GatewayPermission::SshCommandRun, $ssh));
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $operator->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $operator->id,
            'permission' => GatewayPermission::SshFileRead->value,
        ]);
    }

    public function test_non_owner_cannot_manage_users(): void
    {
        $administrator = User::query()->create([
            'name' => 'Administrator',
            'email' => 'administrator@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Administrator->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);

        $this->actingAs($administrator)
            ->get('/admin/users')
            ->assertForbidden();
    }

    public function test_last_recoverable_owner_cannot_be_disabled_or_demoted(): void
    {
        $owner = $this->owner();

        $this->actingAs($owner)
            ->put('/admin/users/'.$owner->id, [
                'name' => $owner->name,
                'email' => $owner->email,
                'role' => GatewayRole::Administrator->value,
                'target_scope_mode' => TargetScopeMode::All->value,
                'access_enabled' => '0',
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertSessionHasErrors('access_enabled');

        $owner->refresh();
        self::assertSame(GatewayRole::Owner, $owner->role);
        self::assertTrue($owner->access_enabled);
    }

    public function test_wrong_current_password_cannot_change_user_access(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();

        $this->actingAs($owner)
            ->put('/admin/users/'.$operator->id, [
                'name' => $operator->name,
                'email' => $operator->email,
                'role' => GatewayRole::Viewer->value,
                'target_scope_mode' => TargetScopeMode::Selected->value,
                'access_enabled' => '1',
                'current_password' => 'WrongHorse!234',
            ])
            ->assertSessionHasErrors('current_password');

        self::assertSame(GatewayRole::Operator, $operator->refresh()->role);
    }

    public function test_site_rule_can_make_one_operator_site_write_only_without_elevation(): void
    {
        $owner = $this->owner();
        $operator = $this->operator();
        $site = $this->site('alpha');

        $this->actingAs($owner)
            ->put(route('admin.users.targets.update', [
                'user' => $operator->id,
                'target' => $site->target_id,
            ], false), [
                'access_rule' => 'allow',
                'denied_permissions' => [
                    GatewayPermission::TargetsView->value,
                    GatewayPermission::WordpressAbilitiesInspect->value,
                    GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
                ],
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertRedirect();

        $access = app(AccessControl::class);

        self::assertFalse($access->allows($operator, GatewayPermission::TargetsView, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesInspect, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteReadonly, $site));
        self::assertTrue($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteMutating, $site));
        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteDestructive, $site));

        $this->assertDatabaseHas('user_target_access', [
            'user_id' => $operator->id,
            'target_record_id' => $site->id,
            'allowed' => true,
        ]);
        $this->assertDatabaseHas('activity_events', [
            'actor_type' => 'administrator',
            'actor_id' => (string) $owner->id,
            'operation' => 'user-target-access-update:'.$operator->id.':alpha',
            'outcome' => 'success',
        ]);
    }

    public function test_all_sites_user_can_explicitly_exclude_one_site(): void
    {
        $owner = $this->owner();
        $administrator = User::query()->create([
            'name' => 'All Sites Admin',
            'email' => 'all-sites@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Administrator->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $this->actingAs($owner)
            ->put(route('admin.users.targets.update', [
                'user' => $administrator->id,
                'target' => $beta->target_id,
            ], false), [
                'access_rule' => 'deny',
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertRedirect();

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($administrator, GatewayPermission::TargetsView, $alpha));
        self::assertFalse($access->allows($administrator, GatewayPermission::TargetsView, $beta));
    }

    public function test_owner_site_overrides_are_rejected_and_owner_remains_unrestricted(): void
    {
        $owner = $this->owner();
        $site = $this->site('alpha');

        $this->actingAs($owner)
            ->put(route('admin.users.targets.update', [
                'user' => $owner->id,
                'target' => $site->target_id,
            ], false), [
                'access_rule' => 'deny',
                'denied_permissions' => [GatewayPermission::TargetsView->value],
                'current_password' => 'CorrectHorse!234',
            ])
            ->assertSessionHasErrors('access_rule');

        self::assertTrue(app(AccessControl::class)->allows(
            $owner,
            GatewayPermission::TargetsRemove,
            $site,
        ));
        self::assertSame(0, DB::table('user_target_access')->where('user_id', $owner->id)->count());
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

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Operator',
            'email' => 'operator-'.uniqid().'@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'disconnected',
        ]);
    }
}
