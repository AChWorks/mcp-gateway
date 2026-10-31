<?php

namespace Tests\Feature\Admin;

use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Models\User;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

#[Group('database-access')]
final class UserAccessFormStateTest extends TestCase
{
    use RefreshDatabase;

    public function test_created_account_reopens_with_exact_saved_controls_and_denials(): void
    {
        $owner = $this->owner();
        $payload = [
            ...$this->fields('operator'),
            'name' => 'Saved Operator', 'email' => 'saved-operator@example.test',
            'password' => 'DifferentHorse!234', 'password_confirmation' => 'DifferentHorse!234',
            'access_enabled' => '0', 'ai_access_enabled' => '1',
            'denied_permissions' => [
                GatewayPermission::TargetsTest->value,
                ...array_map(static fn (GatewayPermission $permission): string => $permission->value, GatewayPermission::sshCapabilities()),
            ],
        ];
        $response = $this->actingAs($owner)->post('/admin/users', $payload)->assertSessionHasNoErrors();
        $user = User::query()->where('email', $payload['email'])->sole();
        $response->assertRedirect(route('admin.users.edit', ['user' => $user->id], false));
        $page = $this->get('/admin/users/'.$user->id.'/edit')->assertOk();
        $this->assertControls($page, 'operator', 'selected', false, true);
        self::assertSame($this->storedDenials($user), $this->checkedDenials($page));
        self::assertContains(GatewayPermission::TargetsTest->value, $this->checkedDenials($page));
    }

    public function test_updated_account_reopens_with_changed_flags_and_exact_saved_denials(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        $this->actingAs($owner)->put('/admin/users/'.$user->id, [
            ...$this->fields(), 'target_scope_mode' => 'all',
            'access_enabled' => '0', 'ai_access_enabled' => '1',
            'denied_permissions' => [GatewayPermission::ActivityView->value],
        ])->assertSessionHasNoErrors()->assertRedirect('/admin/users/'.$user->id.'/edit');
        $page = $this->get('/admin/users/'.$user->id.'/edit')->assertOk();
        $this->assertControls($page, 'viewer', 'all', false, true);
        self::assertSame([GatewayPermission::ActivityView->value], $this->checkedDenials($page));
        self::assertSame($this->storedDenials($user), $this->checkedDenials($page));
    }

    public function test_rejected_ssh_grant_is_visibly_unsaved_and_durable_denials_reappear_on_reopen(): void
    {
        $owner = $this->owner();
        $ssh = array_map(static fn (GatewayPermission $permission): string => $permission->value, GatewayPermission::sshCapabilities());
        $user = app(UserAccessManager::class)->create([
            'name' => 'Managed Operator', 'email' => 'operator@example.test',
            'password' => 'DifferentHorse!234', 'role' => 'operator',
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ], $ssh);
        $url = '/admin/users/'.$user->id.'/edit';
        $attempted = [GatewayPermission::SshCommandRun->value, GatewayPermission::SshFileWrite->value];

        // Removing the SSH read Deny would be a high-trust grant; without
        // Owner acknowledgement the POST fails and returns an unsaved draft.
        $this->actingAs($owner)->from($url)->put('/admin/users/'.$user->id, [
            ...$this->fields('operator'), 'name' => $user->name, 'email' => $user->email,
            'denied_permissions' => $attempted,
        ])->assertRedirect($url)->assertSessionHasErrors('confirm_ssh_permission_changes');

        $draft = $this->get($url)->assertOk()->assertSee('User changes were not saved.');
        self::assertSame($attempted, $this->checkedDenials($draft));
        self::assertSame(1, $this->document($draft)->query('//*[@data-user-save-failed]')->length);
        self::assertSame(1, $this->document($draft)->query('//*[@data-user-permission-state="submitted"]')->length);
        self::assertSame($ssh, $this->storedDenials($user));

        // A subsequent independent GET is the durable truth, not old input.
        $saved = $this->get($url)->assertOk();
        self::assertSame($ssh, $this->checkedDenials($saved));
        self::assertSame(0, $this->document($saved)->query('//*[@data-user-save-failed]')->length);
        self::assertSame(1, $this->document($saved)->query('//*[@data-user-permission-state="saved"]')->length);
    }

    public function test_initial_user_role_hides_ineligible_denials_without_losing_saved_allowed_choices(): void
    {
        $owner = $this->owner();
        $viewer = $this->viewer();
        $page = $this->actingAs($owner)->get('/admin/users/'.$viewer->id.'/edit')->assertOk();
        $xpath = $this->document($page);
        self::assertSame(1, $xpath->query('//label[@data-user-role-choice and @hidden][input[@value="users.manage" and @disabled]]')->length);
        self::assertSame(1, $xpath->query('//label[@data-user-role-choice and @hidden][input[@value="ssh.command.run" and @disabled]]')->length);
        self::assertSame(1, $xpath->query('//label[@data-user-role-choice and not(@hidden)][input[@value="targets.view" and @checked and not(@disabled)]]')->length);
        self::assertSame(1, $xpath->query('//li[@data-user-role-unavailable-item and not(@hidden)][code="users.manage"]')->length);
        self::assertSame(1, $xpath->query('//li[@data-user-role-unavailable-item and @hidden][code="targets.view"]')->length);
        self::assertSame(0, $xpath->query('//*[@data-user-role-owner-note and not(@hidden)]')->length);
        self::assertSame([GatewayPermission::TargetsView->value], $this->checkedDenials($page));
        self::assertStringContainsString('Saved: 1 checked', $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));

        $ownerPage = $this->get('/admin/users/'.$owner->id.'/edit')->assertOk();
        $ownerXPath = $this->document($ownerPage);
        self::assertSame(0, $ownerXPath->query('//label[@data-user-role-choice and not(@hidden)]')->length);
        self::assertSame(1, $ownerXPath->query('//*[@data-user-role-owner-note and not(@hidden)]')->length);
        self::assertSame(1, $ownerXPath->query('//*[@data-user-role-unavailable and @hidden]')->length);
        self::assertSame(1, $ownerXPath->query('//*[@data-user-role-ssh-review and @hidden]')->length);
        self::assertStringContainsString('Saved: 0 checked', $ownerXPath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));

        $create = $this->get('/admin/users/create')->assertOk();
        $createXPath = $this->document($create);
        self::assertSame(1, $createXPath->query('//label[@data-user-role-choice and @hidden][input[@value="users.manage" and @disabled]]')->length);
        self::assertSame(1, $createXPath->query('//label[@data-user-role-choice and not(@hidden)][input[@value="ssh.file.read" and @checked and not(@disabled)]]')->length);
        self::assertStringContainsString('Defaults: 3 checked', $createXPath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
    }

    public function test_native_role_preview_is_read_only_and_renders_selected_role_permissions(): void
    {
        $owner = $this->owner();
        $viewer = $this->viewer();
        $this->actingAs($owner);

        $url = '/admin/users/'.$viewer->id.'/edit';
        $preview = $this->get($url.'?preview_role=operator')->assertOk();
        $xpath = $this->document($preview);
        self::assertSame('operator', $xpath->evaluate('string(//select[@name="role"]/option[@selected]/@value)'));
        self::assertSame(1, $xpath->query('//label[@data-user-role-choice and not(@hidden)][input[@value="ssh.file.read" and not(@disabled)]]')->length);
        self::assertSame(1, $xpath->query('//label[@data-user-role-choice and @hidden][input[@value="users.manage" and @disabled]]')->length);
        self::assertSame(1, $xpath->query('//a[contains(@href,"preview_role=administrator") and ancestor::noscript]')->length);
        self::assertSame(1, $xpath->query('//*[@data-user-permission-state="editing"]')->length);
        self::assertStringContainsString('Unsaved: 1 checked',
            $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
        self::assertSame('viewer', $viewer->fresh()->role->value);
        self::assertSame([GatewayPermission::TargetsView->value], $this->storedDenials($viewer));

        $invalid = $this->get($url.'?preview_role=not-a-role')->assertOk();
        self::assertSame('viewer', $this->document($invalid)
            ->evaluate('string(//select[@name="role"]/option[@selected]/@value)'));
        $create = $this->get('/admin/users/create?preview_role=viewer')->assertOk();
        $xpath = $this->document($create);
        self::assertSame('viewer', $xpath->evaluate('string(//select[@name="role"]/option[@selected]/@value)'));
        self::assertSame(1, $xpath->query('//input[@value="ssh.file.read" and @disabled]')->length);
    }

    public function test_role_ineligible_deny_cannot_silently_disappear_after_successful_submit(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        $url = '/admin/users/'.$user->id.'/edit';

        $this->actingAs($owner)->from($url)->put('/admin/users/'.$user->id, [
            ...$this->fields(), 'denied_permissions' => [
                GatewayPermission::TargetsView->value,
                GatewayPermission::UsersManage->value,
            ],
        ])->assertRedirect($url)->assertSessionHasErrors('denied_permissions');

        $draft = $this->get($url)->assertOk()->assertSee('User changes were not saved.')
            ->assertSee('users.manage');
        self::assertSame(2, count($this->checkedDenials($draft)));
        self::assertSame([GatewayPermission::TargetsView->value], $this->storedDenials($user));
        $saved = $this->get($url)->assertOk();
        self::assertSame([GatewayPermission::TargetsView->value], $this->checkedDenials($saved));
    }

    public function test_role_downgrade_keeps_working_with_previously_saved_but_now_ineligible_denials(): void
    {
        $owner = $this->owner();
        $ssh = array_map(static fn (GatewayPermission $permission): string => $permission->value, GatewayPermission::sshCapabilities());
        $user = app(UserAccessManager::class)->create([
            'name' => 'Downgraded Operator', 'email' => 'downgrade@example.test',
            'password' => 'DifferentHorse!234', 'role' => 'operator',
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ], [GatewayPermission::TargetsView->value, ...$ssh]);
        $url = '/admin/users/'.$user->id.'/edit';

        $this->actingAs($owner)->put('/admin/users/'.$user->id, [
            ...$this->fields('viewer'), 'name' => $user->name, 'email' => $user->email,
            'denied_permissions' => [GatewayPermission::TargetsView->value, ...$ssh],
        ])->assertSessionHasNoErrors()->assertRedirect($url);
        self::assertSame('viewer', $user->fresh()->role->value);
        // The role itself blocks SSH; explicit active Deny storage is
        // normalized to the new ceiling without granting any capability.
        self::assertSame([GatewayPermission::TargetsView->value], $this->storedDenials($user));
        $saved = $this->get($url)->assertOk();
        self::assertSame([GatewayPermission::TargetsView->value], $this->checkedDenials($saved));
        self::assertSame(0, $this->document($saved)->query('//*[@data-user-save-failed]')->length);
    }

    public function test_owner_promotion_with_old_operator_denials_reopens_without_invalid_restrictions(): void
    {
        $owner = $this->owner();
        $oldDenials = [
            GatewayPermission::TargetsView->value,
            GatewayPermission::SshCommandRun->value,
            GatewayPermission::SshFileRead->value,
            GatewayPermission::SshFileWrite->value,
        ];
        $operator = app(UserAccessManager::class)->create([
            'name' => 'Promotable Operator', 'email' => 'promote@example.test',
            'password' => 'DifferentHorse!234', 'role' => 'operator',
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ], $oldDenials);
        $url = '/admin/users/'.$operator->id.'/edit';
        $this->actingAs($owner)->put('/admin/users/'.$operator->id, [
            ...$this->fields('owner'),
            'name' => $operator->name, 'email' => $operator->email,
            'target_scope_mode' => 'all', 'denied_permissions' => $oldDenials,
        ])->assertSessionHasNoErrors()->assertRedirect($url);

        $updated = $operator->fresh();
        self::assertSame('owner', $updated->role->value);
        self::assertSame('all', $updated->target_scope_mode->value);
        self::assertSame([], $this->storedDenials($operator));
        $page = $this->get($url)->assertOk();
        self::assertSame([], $this->checkedDenials($page));
        $xpath = $this->document($page);
        self::assertSame(0, $xpath->query('//label[@data-user-role-choice and not(@hidden)]')->length);
        self::assertSame(1, $xpath->query('//*[@data-user-role-owner-note and not(@hidden)]')->length);
        self::assertStringContainsString('Saved: 0 checked',
            $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
    }

    public function test_owner_cannot_be_shown_success_for_deny_options_that_owner_ignores(): void
    {
        $owner = $this->owner();
        $url = '/admin/users/'.$owner->id.'/edit';

        $this->actingAs($owner)->from($url)->put('/admin/users/'.$owner->id, [
            ...$this->fields('owner'), 'name' => $owner->name, 'email' => $owner->email,
            'target_scope_mode' => 'all',
            'denied_permissions' => [GatewayPermission::TargetsView->value],
        ])->assertRedirect($url)->assertSessionHasErrors('denied_permissions');

        $this->get($url)->assertOk()->assertSee('User changes were not saved.');
        self::assertSame([], $this->storedDenials($owner));
    }

    public function test_edit_validation_error_keeps_an_explicitly_empty_restriction_choice(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        $url = '/admin/users/'.$user->id.'/edit';
        $this->actingAs($owner)->from($url)->put('/admin/users/'.$user->id, [
            ...$this->fields(), 'name' => '', 'target_scope_mode' => 'all',
            'access_enabled' => '0', 'ai_access_enabled' => '1',
            // Browsers omit the array when every Deny checkbox is unchecked.
        ])->assertRedirect($url)->assertSessionHasErrors('name');
        $page = $this->get($url)->assertOk();
        $this->assertControls($page, 'viewer', 'all', false, true);
        self::assertSame([], $this->checkedDenials($page));
        self::assertSame([GatewayPermission::TargetsView->value], $this->storedDenials($user));
    }

    public function test_edit_password_error_keeps_an_explicitly_empty_restriction_choice(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        $url = '/admin/users/'.$user->id.'/edit';
        $this->actingAs($owner)->from($url)->put('/admin/users/'.$user->id, [
            ...$this->fields(), 'current_password' => 'WrongHorse!234',
        ])->assertRedirect($url)->assertSessionHasErrors('current_password');
        self::assertSame([], $this->checkedDenials($this->get($url)->assertOk()));
        self::assertSame([GatewayPermission::TargetsView->value], $this->storedDenials($user));
    }

    public function test_create_validation_error_does_not_restore_default_ssh_checks_to_an_empty_choice(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner)->from('/admin/users/create')->post('/admin/users', [
            ...$this->fields(), 'name' => '',
            'password' => 'DifferentHorse!234', 'password_confirmation' => 'DifferentHorse!234',
        ])->assertRedirect('/admin/users/create')->assertSessionHasErrors('name');
        self::assertSame([], $this->checkedDenials($this->get('/admin/users/create')->assertOk()));
        $this->assertDatabaseMissing('users', ['email' => 'managed-viewer@example.test']);
    }

    public function test_create_password_error_does_not_restore_default_ssh_checks_to_an_empty_choice(): void
    {
        $owner = $this->owner();
        $this->actingAs($owner)->from('/admin/users/create')->post('/admin/users', [
            ...$this->fields(), 'current_password' => 'WrongHorse!234',
            'password' => 'DifferentHorse!234', 'password_confirmation' => 'DifferentHorse!234',
        ])->assertRedirect('/admin/users/create')->assertSessionHasErrors('current_password');
        self::assertSame([], $this->checkedDenials($this->get('/admin/users/create')->assertOk()));
        $this->assertDatabaseMissing('users', ['email' => 'managed-viewer@example.test']);
    }

    public function test_saved_restrictions_are_open_and_historical_keys_do_not_inflate_checked_count(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        DB::table('user_permission_denials')->insert([
            'user_id' => $user->id, 'permission' => 'historical.retired.permission',
        ]);
        $page = $this->actingAs($owner)->get('/admin/users/'.$user->id.'/edit')->assertOk();
        $xpath = $this->document($page);
        self::assertSame([GatewayPermission::TargetsView->value], $this->checkedDenials($page));
        self::assertSame(1, $xpath->query('//details[@id="user-permission-restrictions" and @open]')->length);
        self::assertSame(1, $xpath->query('//label[contains(@class,"permission-option")][input[@value="targets.view" and @checked]][.//*[@data-global-deny-choice="denied"]][.//*[@data-global-deny-choice="not-denied"]]')->length);
        self::assertGreaterThan(0, $xpath->query('//*[@data-global-deny-choice="not-denied"]')->length);
        self::assertStringContainsString('Saved: 1 checked', $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
        self::assertSame(1, $xpath->query('//*[@data-user-permission-state="saved"]')->length);
        $this->assertDatabaseHas('user_permission_denials', ['user_id' => $user->id, 'permission' => 'historical.retired.permission']);
    }

    public function test_successful_empty_restriction_save_reopens_as_saved_zero_without_default_checks(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        $this->actingAs($owner)->put('/admin/users/'.$user->id, $this->fields())
            ->assertSessionHasNoErrors()->assertRedirect('/admin/users/'.$user->id.'/edit');
        $page = $this->get('/admin/users/'.$user->id.'/edit')->assertOk();
        $xpath = $this->document($page);
        self::assertSame([], $this->checkedDenials($page));
        self::assertSame([], $this->storedDenials($user));
        self::assertStringContainsString('Saved: 0 checked', $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
        self::assertSame(1, $xpath->query('//details[@id="user-permission-restrictions" and @open]')->length);
        self::assertGreaterThan(0, $xpath->query('//*[@data-global-deny-choice="denied"]')->length);
        self::assertSame(0, $xpath->query('//label[contains(@class,"permission-option")]/input[@checked]')->length);
        self::assertSame(1, $xpath->query('//*[@data-user-permission-state="saved"]')->length);
        $page->assertSee('group and direct Target restrictions can still block access.');
    }

    public function test_nonempty_failed_selection_is_labelled_unsaved_and_a_later_get_returns_saved_state(): void
    {
        $owner = $this->owner();
        $user = $this->viewer();
        $url = '/admin/users/'.$user->id.'/edit';
        $requested = [GatewayPermission::ActivityView->value, GatewayPermission::DashboardView->value];
        $this->actingAs($owner)->from($url)->put('/admin/users/'.$user->id, [
            ...$this->fields(), 'name' => '', 'denied_permissions' => $requested,
        ])->assertSessionHasErrors('name');
        $draft = $this->get($url)->assertOk();
        self::assertSame($requested, $this->checkedDenials($draft));
        $xpath = $this->document($draft);
        self::assertStringContainsString('Unsaved: 2 checked', $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
        self::assertSame(1, $xpath->query('//*[@data-user-permission-state="submitted"]')->length);
        self::assertSame([GatewayPermission::TargetsView->value], $this->storedDenials($user));
        $saved = $this->get($url)->assertOk();
        self::assertSame([GatewayPermission::TargetsView->value], $this->checkedDenials($saved));
        self::assertSame(1, $this->document($saved)->query('//*[@data-user-permission-state="saved"]')->length);
    }

    public function test_new_form_identifies_default_ssh_checks_without_claiming_a_saved_account(): void
    {
        $page = $this->actingAs($this->owner())->get('/admin/users/create')->assertOk();
        $xpath = $this->document($page);
        self::assertSame(3, count($this->checkedDenials($page)));
        self::assertStringContainsString('Defaults: 3 checked', $xpath->evaluate('string(//details[@id="user-permission-restrictions"]/summary)'));
        self::assertSame(0, $xpath->query('//details[@id="user-permission-restrictions" and @open]')->length);
        self::assertSame(1, $xpath->query('//*[@data-user-permission-state="defaults"]')->length);
    }

    /** @return array<string,string> */
    private function fields(string $role = 'viewer'): array
    {
        return [
            'name' => 'Managed Viewer', 'email' => 'managed-viewer@example.test',
            'role' => $role, 'target_scope_mode' => 'selected',
            'access_enabled' => '1', 'ai_access_enabled' => '0',
            'ssh_permissions_reviewed' => '1', 'current_password' => 'CorrectHorse!234',
        ];
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Gateway Owner', 'email' => 'owner@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
    }

    private function viewer(): User
    {
        return app(UserAccessManager::class)->create([
            'name' => 'Managed Viewer', 'email' => 'managed-viewer@example.test',
            'password' => 'DifferentHorse!234', 'role' => 'viewer',
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ], [GatewayPermission::TargetsView->value]);
    }

    /** @return list<string> */
    private function storedDenials(User $user): array
    {
        return DB::table('user_permission_denials')->where('user_id', $user->id)
            ->orderBy('permission')->pluck('permission')->all();
    }

    /**
     * @param  TestResponse<Response>  $response
     * @return list<string>
     */
    private function checkedDenials(TestResponse $response): array
    {
        $xpath = $this->document($response);
        $result = [];
        foreach ($xpath->query('//input[@name="denied_permissions[]" and @type="checkbox" and @checked]') as $input) {
            self::assertInstanceOf(DOMElement::class, $input);
            $result[] = $input->getAttribute('value');
        }
        sort($result);

        return $result;
    }

    /** @param TestResponse<Response> $response */
    private function assertControls(TestResponse $response, string $role, string $scope, bool $enabled, bool $ai): void
    {
        $xpath = $this->document($response);
        self::assertSame($role, $xpath->evaluate('string(//select[@name="role"]/option[@selected]/@value)'));
        self::assertSame($scope, $xpath->evaluate('string(//select[@name="target_scope_mode"]/option[@selected]/@value)'));
        self::assertSame($enabled, $xpath->query('//input[@id="access_enabled" and @checked]')->length === 1);
        self::assertSame($ai, $xpath->query('//input[@id="ai_access_enabled" and @checked]')->length === 1);
    }

    /** @param TestResponse<Response> $response */
    private function document(TestResponse $response): DOMXPath
    {
        $document = new DOMDocument;
        $document->loadHTML($response->getContent(), LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);

        return new DOMXPath($document);
    }
}
