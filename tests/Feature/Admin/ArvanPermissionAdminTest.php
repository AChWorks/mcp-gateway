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
use Tests\TestCase;

final class ArvanPermissionAdminTest extends TestCase
{
    use RefreshDatabase;

    public function test_arvan_capabilities_are_editable_in_user_group_and_matching_target_forms(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $group = TargetGroup::query()->create(['name' => 'Arvan ACL group']);
        $target = $this->target('arvancloud', 'arvan-acl-ui');

        $this->actingAs($owner);
        foreach (['/admin/users/create', '/admin/users/'.$user->id.'/edit',
            '/admin/target-groups/create', '/admin/target-groups/'.$group->id.'/edit'] as $url) {
            $page = $this->get($url)->assertOk()->assertSee('ArvanCloud API');
            foreach ($this->arvanPermissions() as $permission) {
                // In User forms role-ineligible permissions are read-only,
                // but every supported capability must be discoverable.
                $page->assertSee($permission->value);
            }
        }

        // Adding an enum permission without exposing it on the shared
        // User/Group page must fail the test on future connector releases.
        $groupCatalog = $this->get('/admin/target-groups/create')->assertOk();
        foreach (GatewayPermission::targetScoped() as $permission) {
            $groupCatalog->assertSee('value="'.$permission->value.'"', false);
        }

        $page = $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->assertSee('ArvanCloud API')->assertSee('Shared Target management');
        foreach ($this->arvanPermissions() as $permission) {
            $page->assertSee('value="'.$permission->value.'"', false);
        }
        $page->assertDontSee('value="wordpress.abilities.inspect"', false)
            ->assertDontSee('value="ssh.command.run"', false)
            ->assertDontSee('Direct SSH')
            ->assertDontSee('WordPress (WP AI Bridge)');
    }

    public function test_new_viewer_can_be_created_with_explicit_arvan_read_deny(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner)->post('/admin/users', [
            'name' => 'Arvan read limited',
            'email' => 'arvan-viewer@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => 'viewer',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'denied_permissions' => [GatewayPermission::ArvanApiRead->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $user = User::query()->where('email', 'arvan-viewer@example.test')->sole();
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
        ]);
        $this->actingAs($owner)->get('/admin/users/'.$user->id.'/edit')
            ->assertOk()->assertSee('ArvanCloud API')
            ->assertSee('value="arvan.api.read"', false);
    }

    public function test_global_and_direct_target_arvan_denials_are_saved_and_enforced(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $target = $this->target('arvancloud', 'arvan-direct-acl');
        $access = app(AccessControl::class);
        $manager = app(UserAccessManager::class);

        $this->actingAs($owner)->put('/admin/users/'.$user->id, [
            'name' => $user->name,
            'email' => $user->email,
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'denied_permissions' => [GatewayPermission::ArvanApiRead->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseHas('user_permission_denials', [
            'user_id' => $user->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
        ]);

        // Existing cross-connector denials are historical/inapplicable on
        // this Arvan Target, but saving its real Arvan checkbox must not
        // erase their stored evidence or display them as editable controls.
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $user->id,
            'target_record_id' => $target->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()
            ->assertSee('name="denied_permissions[]" value="wordpress.abilities.execute.readonly"', false)
            ->assertDontSee('WordPress (WP AI Bridge)');

        $this->actingAs($owner)->put('/admin/users/'.$user->id.'/targets/'.$target->target_id, [
            'access_rule' => 'allow',
            'denied_permissions' => [
                GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
                GatewayPermission::ArvanApiWrite->value,
            ],
            'target_revision' => $manager->targetRuleRevision($user, $target),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => GatewayPermission::ArvanApiWrite->value,
        ]);
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteReadonly->value,
        ]);
        self::assertTrue($access->allows($user, GatewayPermission::ArvanApiInspect, $target));
        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiRead, $target));
        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiWrite, $target));

        $this->actingAs($owner)->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->assertSee('value="arvan.api.write"', false);
    }

    public function test_group_arvan_denials_apply_and_other_connector_denials_survive_target_edit(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $arvan = $this->target('arvancloud', 'arvan-group-acl');
        $wordpress = $this->target('wp_ai_bridge', 'wp-acl-preservation');
        $access = app(AccessControl::class);
        $manager = app(UserAccessManager::class);

        $this->actingAs($owner)->post('/admin/target-groups', [
            'name' => 'Read-only Arvan',
            'denied_permissions' => [GatewayPermission::ArvanApiWrite->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $group = TargetGroup::query()->where('name', 'Read-only Arvan')->sole();
        $this->assertDatabaseHas('target_group_permission_denials', [
            'target_group_id' => $group->id,
            'permission' => GatewayPermission::ArvanApiWrite->value,
        ]);

        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id.'/users/'.$user->id, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id.'/targets/'.$arvan->target_id, [
            'assigned' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        self::assertTrue($access->allows($user, GatewayPermission::ArvanApiRead, $arvan));
        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiWrite, $arvan));

        $this->actingAs($owner)->put('/admin/target-groups/'.$group->id, [
            'name' => $group->name,
            'denied_permissions' => [GatewayPermission::ArvanApiRead->value],
            'denial_revision' => app(TargetGroupManager::class)->denialRevision($group),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        self::assertFalse($access->allows($user, GatewayPermission::ArvanApiRead, $arvan));
        self::assertTrue($access->allows($user, GatewayPermission::ArvanApiWrite, $arvan));

        // Older cross-connector denial rows must remain intact when a
        // WordPress Target rule is edited through its filtered UI.
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $user->id,
            'target_record_id' => $wordpress->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $page = $this->get('/admin/users/'.$user->id.'/targets/'.$wordpress->target_id.'/edit')
            ->assertOk()->assertSee('WordPress (WP AI Bridge)')
            ->assertSee('name="denied_permissions[]" value="arvan.api.read"', false)
            ->assertDontSee('value="arvan.api.write"', false)
            ->assertDontSee('ArvanCloud API');

        $this->put('/admin/users/'.$user->id.'/targets/'.$wordpress->target_id, [
            'access_rule' => 'allow',
            'denied_permissions' => [
                GatewayPermission::ArvanApiRead->value,
                GatewayPermission::WordpressAbilitiesExecuteMutating->value,
            ],
            'target_revision' => $manager->targetRuleRevision($user, $wordpress),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $wordpress->id,
            'permission' => GatewayPermission::ArvanApiRead->value,
        ]);
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $wordpress->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
        ]);
    }

    public function test_role_downgrade_cannot_erase_historical_arvan_and_cross_connector_target_denials(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $user->forceFill(['role' => GatewayRole::Administrator->value])->save();
        $target = $this->target('arvancloud', 'arvan-historical-denials');
        $manager = app(UserAccessManager::class);
        $denials = [
            GatewayPermission::ArvanApiDestructive->value,
            GatewayPermission::ArvanApiUnclassified->value,
            GatewayPermission::WordpressAbilitiesExecuteDestructive->value,
            GatewayPermission::SshCommandRun->value,
        ];

        $manager->updateTargetRule(
            $user, $target, 'allow', [
                GatewayPermission::ArvanApiDestructive->value,
                GatewayPermission::ArvanApiUnclassified->value,
            ], false, $manager->targetRuleRevision($user, $target),
        );
        // Historical foreign-connector records may be present from an
        // earlier release or import, but cannot be introduced anew here.
        foreach ([
            GatewayPermission::WordpressAbilitiesExecuteDestructive,
            GatewayPermission::SshCommandRun,
        ] as $foreign) {
            DB::table('user_target_permission_denials')->insert([
                'user_id' => $user->id,
                'target_record_id' => $target->id,
                'permission' => $foreign->value,
                'created_at' => now(), 'updated_at' => now(),
            ]);
        }
        $this->actingAs($owner);
        $this->put('/admin/users/'.$user->id, [
            'name' => $user->name, 'email' => $user->email,
            'role' => 'viewer', 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        self::assertSame(GatewayRole::Viewer, $user->fresh()->role);
        $viewerForm = (string) $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->getContent();
        foreach ([GatewayPermission::ArvanApiDestructive, GatewayPermission::ArvanApiUnclassified] as $denied) {
            $input = $this->targetPermissionInput($viewerForm, $denied);
            self::assertStringContainsString('checked', $input);
            self::assertStringContainsString('disabled', $input);
        }

        // A reduced-role form omitting the now-unavailable, old checkboxes
        // must not turn those preserved restrictions into implicit grants.
        $url = '/admin/users/'.$user->id.'/targets/'.$target->target_id;
        $this->put($url, [
            'access_rule' => 'allow', 'denied_permissions' => [],
            'target_revision' => $manager->targetRuleRevision($user->fresh(), $target),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        foreach ($denials as $denial) {
            $this->assertDatabaseHas('user_target_permission_denials', [
                'user_id' => $user->id, 'target_record_id' => $target->id,
                'permission' => $denial,
            ]);
        }

        $this->put('/admin/users/'.$user->id, [
            'name' => $user->name, 'email' => $user->email,
            'role' => 'administrator', 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
        $access = app(AccessControl::class);
        self::assertSame(GatewayRole::Administrator, $user->fresh()->role);
        $adminForm = (string) $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->getContent();
        foreach ([GatewayPermission::ArvanApiDestructive, GatewayPermission::ArvanApiUnclassified] as $denied) {
            $input = $this->targetPermissionInput($adminForm, $denied);
            self::assertStringContainsString('checked', $input);
            self::assertStringNotContainsString('disabled', $input);
        }
        self::assertTrue($access->allows($user->fresh(), GatewayPermission::ArvanApiRead, $target));
        self::assertFalse($access->allows($user->fresh(), GatewayPermission::ArvanApiDestructive, $target));
        self::assertFalse($access->allows($user->fresh(), GatewayPermission::ArvanApiUnclassified, $target));
        foreach ($denials as $denial) {
            $this->assertDatabaseHas('user_target_permission_denials', [
                'user_id' => $user->id, 'target_record_id' => $target->id,
                'permission' => $denial,
            ]);
        }
    }

    public function test_role_promotion_invalidates_older_viewer_form_before_it_can_clear_newly_eligible_deny(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $user->forceFill(['role' => GatewayRole::Administrator->value])->save();
        $target = $this->target('arvancloud', 'arvan-role-race');
        $manager = app(UserAccessManager::class);
        $url = '/admin/users/'.$user->id.'/targets/'.$target->target_id;

        $manager->updateTargetRule(
            $user, $target, 'allow', [GatewayPermission::ArvanApiDestructive->value],
            false, $manager->targetRuleRevision($user, $target),
        );
        $this->actingAs($owner)->put('/admin/users/'.$user->id, [
            'name' => $user->name, 'email' => $user->email,
            'role' => 'viewer', 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $oldViewerRevision = $manager->targetRuleRevision($user->fresh(), $target);
        $view = (string) $this->get($url.'/edit')->assertOk()->getContent();
        self::assertStringContainsString('disabled',
            $this->targetPermissionInput($view, GatewayPermission::ArvanApiDestructive));

        // The Deny rows did not change, but the Role now makes those Denies
        // editable. Any pre-promotion form revision must become stale.
        $this->put('/admin/users/'.$user->id, [
            'name' => $user->name, 'email' => $user->email,
            'role' => 'administrator', 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $newRevision = $manager->targetRuleRevision($user->fresh(), $target);
        self::assertNotSame($oldViewerRevision, $newRevision);
        $this->put($url, [
            'access_rule' => 'allow', 'denied_permissions' => [],
            'target_revision' => $oldViewerRevision,
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('target_revision');
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => GatewayPermission::ArvanApiDestructive->value,
        ]);
        self::assertFalse(app(AccessControl::class)->allows(
            $user->fresh(), GatewayPermission::ArvanApiDestructive, $target,
        ));
        $this->put($url, [
            'access_rule' => 'allow',
            'denied_permissions' => [GatewayPermission::ArvanApiDestructive->value],
            'target_revision' => $newRevision,
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();
    }

    public function test_new_role_excluded_target_denial_is_rejected_instead_of_appearing_saved(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $user->forceFill(['role' => GatewayRole::Viewer->value])->save();
        $target = $this->target('arvancloud', 'arvan-outside-role');
        $manager = app(UserAccessManager::class);
        $this->actingAs($owner);
        $viewerForm = (string) $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')
            ->assertOk()->getContent();
        $input = $this->targetPermissionInput($viewerForm, GatewayPermission::ArvanApiDestructive);
        self::assertStringContainsString('disabled', $input);
        $this->put('/admin/users/'.$user->id.'/targets/'.$target->target_id, [
            'access_rule' => 'allow',
            'denied_permissions' => [GatewayPermission::ArvanApiDestructive->value],
            'target_revision' => $manager->targetRuleRevision($user, $target),
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('denied_permissions');
        $this->assertDatabaseMissing('user_target_access', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
        ]);
        $this->assertDatabaseMissing('user_target_permission_denials', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
            'permission' => GatewayPermission::ArvanApiDestructive->value,
        ]);

        // Also reject a new restriction for another connector, even when
        // the Role would otherwise include that permission.
        $user->forceFill(['role' => GatewayRole::Administrator->value])->save();
        $this->put('/admin/users/'.$user->id.'/targets/'.$target->target_id, [
            'access_rule' => 'allow',
            'denied_permissions' => [GatewayPermission::WordpressAbilitiesInspect->value],
            'target_revision' => $manager->targetRuleRevision($user, $target),
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('denied_permissions');
        $this->assertDatabaseMissing('user_target_access', [
            'user_id' => $user->id, 'target_record_id' => $target->id,
        ]);
    }

    public function test_stale_arvan_wordpress_and_ssh_target_forms_cannot_replace_newer_denials_or_scope(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $manager = app(UserAccessManager::class);
        $this->actingAs($owner);

        foreach ([
            ['arvancloud', GatewayPermission::ArvanApiRead, false],
            ['wp_ai_bridge', GatewayPermission::WordpressAbilitiesInspect, false],
            ['ssh_direct', GatewayPermission::SshFileWrite, true],
        ] as [$connector, $denial, $ssh]) {
            $target = $this->target($connector, 'stale-'.str_replace('_', '-', $connector));
            $url = '/admin/users/'.$user->id.'/targets/'.$target->target_id;
            $oldRevision = $manager->targetRuleRevision($user, $target);
            $this->get($url.'/edit')->assertOk()->assertSee($oldRevision);

            $manager->updateTargetRule(
                $user, $target, 'allow', [$denial->value],
                $ssh, $oldRevision,
            );
            $newRevision = $manager->targetRuleRevision($user, $target);
            self::assertNotSame($oldRevision, $newRevision);
            $operation = 'user-target-access-update:'.$user->id.':'.$target->target_id;
            $auditCount = DB::table('activity_events')->where('operation', $operation)->count();

            $this->put($url, [
                'access_rule' => 'deny', 'denied_permissions' => [],
                'target_revision' => $oldRevision,
                'confirm_ssh_target_changes' => $ssh ? '1' : '0',
                'current_password' => 'CorrectHorse!234',
            ])->assertSessionHasErrors('target_revision');
            $this->assertDatabaseHas('user_target_access', [
                'user_id' => $user->id, 'target_record_id' => $target->id,
                'allowed' => 1,
            ]);
            $this->assertDatabaseHas('user_target_permission_denials', [
                'user_id' => $user->id, 'target_record_id' => $target->id,
                'permission' => $denial->value,
            ]);
            self::assertSame($auditCount, DB::table('activity_events')
                ->where('operation', $operation)->count());
            $this->get($url.'/edit')->assertOk()->assertSee($newRevision);
            $this->put($url, [
                'access_rule' => 'inherit', 'denied_permissions' => [$denial->value],
                'target_revision' => $newRevision,
                'confirm_ssh_target_changes' => $ssh ? '1' : '0',
                'current_password' => 'CorrectHorse!234',
            ])->assertAdminRedirect()->assertSessionHasNoErrors();
            $this->assertDatabaseMissing('user_target_access', [
                'user_id' => $user->id, 'target_record_id' => $target->id,
            ]);
            $this->assertDatabaseHas('user_target_permission_denials', [
                'user_id' => $user->id, 'target_record_id' => $target->id,
                'permission' => $denial->value,
            ]);

            // Missing revisions are not a bypass even when the new payload
            // would otherwise be valid.
            $this->put($url, [
                'access_rule' => 'deny', 'denied_permissions' => [$denial->value],
                'confirm_ssh_target_changes' => '1',
                'current_password' => 'CorrectHorse!234',
            ])->assertSessionHasErrors('target_revision');
        }
    }

    public function test_ssh_target_preserves_ineligible_denials_and_never_skips_owner_review(): void
    {
        $owner = $this->owner();
        $user = $this->operator();
        $user->forceFill(['role' => GatewayRole::Administrator->value])->save();
        $ssh = $this->target('ssh_direct', 'historical-ssh-denies');
        $manager = app(UserAccessManager::class);
        $url = '/admin/users/'.$user->id.'/targets/'.$ssh->target_id;
        $this->actingAs($owner);

        $manager->updateTargetRule(
            $user, $ssh, 'allow', [
                GatewayPermission::SshCommandRun->value,
                GatewayPermission::SshFileWrite->value,
            ], true, $manager->targetRuleRevision($user, $ssh),
        );
        $this->actingAs($owner)->put('/admin/users/'.$user->id, [
            'name' => $user->name, 'email' => $user->email,
            'role' => 'viewer', 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        $form = (string) $this->get($url.'/edit')->assertOk()->getContent();
        self::assertStringContainsString('disabled',
            $this->targetPermissionInput($form, GatewayPermission::SshCommandRun));
        $this->put($url, [
            'access_rule' => 'allow', 'denied_permissions' => [],
            'target_revision' => $manager->targetRuleRevision($user->fresh(), $ssh),
            'current_password' => 'CorrectHorse!234',
        ])->assertAdminRedirect()->assertSessionHasNoErrors();

        foreach ([GatewayPermission::SshCommandRun, GatewayPermission::SshFileWrite] as $denied) {
            $this->assertDatabaseHas('user_target_permission_denials', [
                'user_id' => $user->id, 'target_record_id' => $ssh->id,
                'permission' => $denied->value,
            ]);
        }
        $this->put($url, [
            'access_rule' => 'deny', 'denied_permissions' => [],
            'target_revision' => $manager->targetRuleRevision($user, $ssh),
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_target_changes');
        $this->assertDatabaseHas('user_target_access', [
            'user_id' => $user->id, 'target_record_id' => $ssh->id,
            'allowed' => 1,
        ]);
        self::assertFalse(app(AccessControl::class)->allows(
            $user->fresh(), GatewayPermission::SshCommandRun, $ssh,
        ));
    }

    private function targetPermissionInput(string $html, GatewayPermission $permission): string
    {
        $pattern = '/<input[^>]*name="denied_permissions\[\]"[^>]*value="'
            .preg_quote($permission->value, '/').'"[^>]*>/s';
        self::assertSame(1, preg_match($pattern, $html, $matches));

        return $matches[0];
    }

    /** @return list<GatewayPermission> */
    private function arvanPermissions(): array
    {
        return [
            GatewayPermission::ArvanApiInspect,
            GatewayPermission::ArvanApiRead,
            GatewayPermission::ArvanApiWrite,
            GatewayPermission::ArvanApiDestructive,
            GatewayPermission::ArvanApiUnclassified,
        ];
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner',
            'email' => 'acl-owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'ACL Operator',
            'email' => 'acl-operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true,
        ]);
    }

    private function target(string $connector, string $id): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => 'ACL '.$id,
            'connector_type' => $connector,
        ]);
    }
}
