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
