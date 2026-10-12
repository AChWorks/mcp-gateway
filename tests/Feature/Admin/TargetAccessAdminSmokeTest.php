<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class TargetAccessAdminSmokeTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_user_and_group_pages_render_on_target_schema(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);

        $this->get('/admin/users')->assertOk();
        $this->get('/admin/users/create')->assertOk();
        $this->get('/admin/target-groups')->assertOk();
        $this->get('/admin/target-groups/create')->assertOk();
        $this->get('/admin/activity')->assertOk();

        $user = app(UserAccessManager::class)->create([
            'name' => 'Operator',
            'email' => 'operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        $target = $this->target();
        $group = TargetGroup::query()->create(['name' => 'Managed targets']);

        $this->get('/admin/users/'.$user->id.'/edit')->assertOk();
        $this->get('/admin/users/'.$user->id.'/targets')->assertOk();
        $this->get('/admin/users/'.$user->id.'/targets/'.$target->target_id.'/edit')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/edit')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/users')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/targets')->assertOk();
        $this->get('/admin/target-groups/'.$group->id.'/targets/'.$target->target_id.'/edit')->assertOk();
    }

    public function test_owner_can_create_user_then_assign_direct_target_and_group_membership(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);
        $this->post('/admin/users', [
            'name' => 'Limited',
            'email' => 'limited@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $user = User::query()->where('email', 'limited@example.test')->firstOrFail();
        self::assertSame('selected', $user->getRawOriginal('target_scope_mode'));
        self::assertSame('ssh.command.run', DB::table('user_permission_denials')
            ->where('user_id', $user->id)
            ->where('permission', 'ssh.command.run')->value('permission'));

        $target = $this->target();
        $this->put('/admin/users/'.$user->id.'/targets/'.$target->target_id, [
            'access_rule' => 'allow',
            'current_password' => 'CorrectHorse!234',
            'confirm_ssh_target_changes' => '1',
            'target_revision' => app(UserAccessManager::class)->targetRuleRevision($user, $target),
        ])->assertRedirect()->assertSessionHasNoErrors();

        $this->assertDatabaseHas('user_target_access', [
            'target_record_id' => $target->getKey(),
            'user_id' => $user->id,
            'allowed' => true,
        ]);

        $this->post('/admin/target-groups', [
            'name' => 'Operations',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $group = TargetGroup::query()->where('name', 'Operations')->firstOrFail();
        $membershipUrl = '/admin/target-groups/'.$group->getKey().'/targets/'.$target->target_id;
        $this->put($membershipUrl, [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_group_changes');
        self::assertFalse($group->targets()->whereKey($target->getKey())->exists());

        $this->put($membershipUrl, [
            'assigned' => '1',
            'current_password' => 'CorrectHorse!234',
            'confirm_ssh_group_changes' => '1',
        ])->assertRedirect()->assertSessionHasNoErrors();

        self::assertTrue($group->targets()->whereKey($target->getKey())->exists());
    }

    public function test_nonowner_cannot_administer_target_groups(): void
    {
        $owner = $this->owner();
        $operator = app(UserAccessManager::class)->create([
            'name' => 'Operator',
            'email' => 'operator@example.test',
            'password' => 'DifferentHorse!234',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], []);
        $this->actingAs($operator)
            ->get('/admin/target-groups')
            ->assertForbidden();
        $this->actingAs($owner)->get('/admin/target-groups')->assertOk();
    }

    public function test_stale_ssh_target_rule_form_cannot_remove_newer_denial_even_with_old_confirmation(): void
    {
        $owner = $this->owner();
        $manager = app(UserAccessManager::class);
        $operator = $manager->create([
            'name' => 'Confirmed SSH operator',
            'email' => 'stale-ssh-rule@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], [], true);
        $target = $this->target();
        $this->actingAs($owner);

        $url = '/admin/users/'.$operator->id.'/targets/'.$target->target_id;
        $this->get($url.'/edit')->assertOk()->assertSee('name="target_revision"', false);
        $originalRevision = $manager->targetRuleRevision($operator, $target);
        $this->put($url, [
            'access_rule' => 'allow',
            'target_revision' => $originalRevision,
            'confirm_ssh_target_changes' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors();

        $access = app(AccessControl::class);
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $staleRevision = $manager->targetRuleRevision($operator, $target);
        // Another legitimate Owner writes a new denial before stale form A.
        $manager->updateTargetRule(
            $operator, $target, 'allow',
            [GatewayPermission::SshCommandRun->value],
            true, $staleRevision,
        );
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($url, [
            'access_rule' => 'allow', 'target_revision' => $staleRevision,
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('confirm_ssh_target_changes');

        $this->put($url, [
            'access_rule' => 'allow', 'target_revision' => $staleRevision,
            'confirm_ssh_target_changes' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('target_revision');

        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $operator->id,
            'target_record_id' => $target->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $this->put($url, [
            'access_rule' => 'allow',
            'target_revision' => $manager->targetRuleRevision($operator, $target),
            'confirm_ssh_target_changes' => '1',
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));
    }

    public function test_password_and_missing_ssh_confirmation_errors_never_rebind_stale_denials_to_new_revision(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner);
        $manager = app(UserAccessManager::class);
        $operator = $manager->create([
            'name' => 'Stale form SSH operator',
            'email' => 'stale-recovery@example.test',
            'password' => 'DifferentHorse!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ], [], true);
        $target = $this->target();
        $url = '/admin/users/'.$operator->id.'/targets/'.$target->target_id;
        $edit = $url.'/edit';

        $manager->updateTargetRule($operator, $target, 'allow', [
            GatewayPermission::SshFileRead->value,
        ], true, $manager->targetRuleRevision($operator, $target));
        $h0 = $manager->targetRuleRevision($operator, $target);
        $this->get($edit)->assertOk()->assertSee('name="target_revision" value="'.$h0.'"', false);

        // A second Owner adds a denial after the edit page was opened.
        $manager->updateTargetRule($operator, $target, 'allow', [
            GatewayPermission::SshFileRead->value,
            GatewayPermission::SshCommandRun->value,
        ], true, $h0);
        $h1 = $manager->targetRuleRevision($operator, $target);

        $oldForm = [
            'access_rule' => 'allow',
            'denied_permissions' => [GatewayPermission::SshFileRead->value],
            'target_revision' => $h0,
            'confirm_ssh_target_changes' => '1',
        ];
        $this->from($edit)->put($url, [
            ...$oldForm, 'current_password' => 'WrongHorse!234',
        ])->assertRedirect($edit)->assertSessionHasErrors('current_password');

        $page = $this->get($edit)->assertOk()
            ->assertSee('name="target_revision" value="'.$h1.'"', false)
            ->assertSee('changed since you opened this form');
        $html = (string) $page->getContent();
        self::assertTrue($this->formCheckboxChecked($html, 'denied_permissions[]', GatewayPermission::SshFileRead->value));
        self::assertTrue($this->formCheckboxChecked($html, 'denied_permissions[]', GatewayPermission::SshCommandRun->value));
        self::assertFalse($this->formCheckboxChecked($html, 'confirm_ssh_target_changes', '1'));

        // The user now confirms exactly the current displayed restrictions.
        $this->put($url, [
            ...$oldForm,
            'target_revision' => $h1,
            'denied_permissions' => [GatewayPermission::SshFileRead->value, GatewayPermission::SshCommandRun->value],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseHas('user_target_permission_denials', [
            'user_id' => $operator->id,
            'target_record_id' => $target->id,
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);

        // Also exercise the missing SSH approval validation path (correct password).
        $manager->updateTargetRule($operator, $target, 'allow', [
            GatewayPermission::SshFileRead->value,
            GatewayPermission::SshCommandRun->value,
            GatewayPermission::SshFileWrite->value,
        ], true, $h1);
        $h2 = $manager->targetRuleRevision($operator, $target);
        $this->from($edit)->put($url, [
            'access_rule' => 'allow',
            'denied_permissions' => [GatewayPermission::SshFileRead->value, GatewayPermission::SshCommandRun->value],
            'target_revision' => $h1,
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect($edit)->assertSessionHasErrors('confirm_ssh_target_changes');
        $page = $this->get($edit)->assertOk()
            ->assertSee('name="target_revision" value="'.$h2.'"', false);
        $html = (string) $page->getContent();
        self::assertTrue($this->formCheckboxChecked($html, 'denied_permissions[]', GatewayPermission::SshFileWrite->value));
        self::assertFalse($this->formCheckboxChecked($html, 'confirm_ssh_target_changes', '1'));

        // A missing revision must never let flashed permission values be
        // treated as reviewed against whatever the database contains now.
        $this->from($edit)->put($url, [
            'access_rule' => 'allow',
            'denied_permissions' => [GatewayPermission::SshFileRead->value],
            'current_password' => 'WrongHorse!234',
            'confirm_ssh_target_changes' => '1',
        ])->assertRedirect($edit)->assertSessionHasErrors('current_password');
        $page = $this->get($edit)->assertOk()
            ->assertSee('name="target_revision" value="'.$h2.'"', false);
        $html = (string) $page->getContent();
        self::assertTrue($this->formCheckboxChecked($html, 'denied_permissions[]', GatewayPermission::SshFileWrite->value));
        self::assertFalse($this->formCheckboxChecked($html, 'confirm_ssh_target_changes', '1'));

        // A current, matching revision may restore the Owner's intentionally
        // unchecked boxes after an unrelated validation failure.
        $this->from($edit)->put($url, [
            'access_rule' => 'allow',
            'target_revision' => $h2,
            'confirm_ssh_target_changes' => '1',
            'current_password' => 'WrongHorse!234',
        ])->assertRedirect($edit)->assertSessionHasErrors('current_password');
        $page = $this->get($edit)->assertOk();
        $html = (string) $page->getContent();
        self::assertFalse($this->formCheckboxChecked($html, 'denied_permissions[]', GatewayPermission::SshCommandRun->value));
        self::assertTrue($this->formCheckboxChecked($html, 'confirm_ssh_target_changes', '1'));
        self::assertSame($h2, $manager->targetRuleRevision($operator, $target));
    }

    private function formCheckboxChecked(string $html, string $name, string $value): bool
    {
        $document = new \DOMDocument;
        $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING);
        $inputs = (new \DOMXPath($document))->query('//input[@name="'.$name.'"]');

        foreach ($inputs as $input) {
            if ($input instanceof \DOMElement && $input->getAttribute('value') === $value) {
                return $input->hasAttribute('checked');
            }
        }

        self::fail('Expected permission checkbox is missing: '.$name.'='.$value);
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway owner',
            'email' => 'owner@example.test',
            'password' => 'CorrectHorse!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function target(): Target
    {
        return Target::query()->create([
            'target_id' => 'demo-server',
            'display_name' => 'Demo server',
            'connector_type' => 'ssh_direct',
        ]);
    }
}
