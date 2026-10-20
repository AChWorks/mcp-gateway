<?php

namespace Tests\Feature\Admin;

use App\Application\Access\TargetGroupManager;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class WordpressPublishGrantAdminTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_and_revoke_only_explicit_assigned_profile_group_grants(): void
    {
        [$owner, $publisher, $group] = $this->actors();
        $url = route('admin.users.publishing.index', ['user' => $publisher->id]);
        $this->actingAs($owner)->get($url)->assertOk()
            ->assertSee('Explicit scoped publication authority')
            ->assertSee('Grant scoped publication');

        $input = ['group_id' => $group->id, 'current_password' => 'CorrectHorse!234'];
        $this->post($url, [...$input, 'current_password' => 'wrong'])->assertSessionHasErrors('current_password');
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());

        $this->post($url, $input)->assertRedirect($url)->assertSessionHasNoErrors();
        $this->assertDatabaseHas('wordpress_publish_group_grants', [
            'user_id' => $publisher->id, 'target_group_id' => $group->id,
        ]);
        $this->post($url, $input)->assertRedirect($url);
        self::assertSame(1, DB::table('wordpress_publish_group_grants')->count());

        $id = DB::table('wordpress_publish_group_grants')->value('id');
        $delete = route('admin.users.publishing.destroy', ['user' => $publisher->id, 'grant' => $id]);
        $this->delete($delete, ['current_password' => 'wrong'])->assertSessionHasErrors('current_password');
        self::assertSame(1, DB::table('wordpress_publish_group_grants')->count());
        $this->delete($delete, ['current_password' => 'CorrectHorse!234'])->assertRedirect($url);
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());
        $this->assertDatabaseHas('activity_events', ['operation' => 'wordpress-publish-grant-revoke']);
    }

    public function test_non_owner_and_unassigned_or_non_publisher_grants_cannot_be_created(): void
    {
        [$owner, $publisher, $group] = $this->actors();
        $url = route('admin.users.publishing.index', ['user' => $publisher->id]);
        $input = ['group_id' => $group->id, 'current_password' => 'CorrectHorse!234'];

        $this->actingAs($publisher)->get($url)->assertForbidden();
        $this->post($url, $input)->assertForbidden();
        $this->actingAs($owner);

        DB::table('target_group_users')->where('user_id', $publisher->id)->delete();
        $this->post($url, $input)->assertSessionHasErrors('group_id');
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());
        $group->users()->attach($publisher->id);
        $publisher->forceFill(['role' => GatewayRole::Viewer->value])->save();
        $this->post($url, $input)->assertSessionHasErrors('group_id');
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());
    }

    public function test_revoking_group_membership_and_disabling_or_demoting_user_clear_dormant_grants(): void
    {
        [$owner, $publisher, $group] = $this->actors();
        $url = route('admin.users.publishing.index', ['user' => $publisher->id]);
        $this->actingAs($owner);
        $input = ['group_id' => $group->id, 'current_password' => 'CorrectHorse!234'];

        $this->post($url, $input)->assertSessionHasNoErrors();
        app(TargetGroupManager::class)->updateUserAssignment($group, $publisher, false);
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());

        app(TargetGroupManager::class)->updateUserAssignment($group, $publisher, true);
        $this->post($url, $input)->assertSessionHasNoErrors();
        app(UserAccessManager::class)->update($publisher, [
            'name' => $publisher->name, 'email' => $publisher->email,
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected', 'access_enabled' => false,
        ], []);
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());

        $publisher->forceFill(['access_enabled' => true])->save();
        $this->post($url, $input)->assertSessionHasNoErrors();
        app(UserAccessManager::class)->update($publisher, [
            'name' => $publisher->name, 'email' => $publisher->email,
            'role' => GatewayRole::Viewer->value,
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ], []);
        self::assertSame(0, DB::table('wordpress_publish_group_grants')->count());
    }

    /** @return array{User,User,TargetGroup} */
    private function actors(): array
    {
        $owner = User::query()->create([
            'name' => 'Gateway Owner', 'email' => 'publisher-owner@example.test',
            'password' => 'CorrectHorse!234', 'role' => GatewayRole::Owner->value,
            'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $publisher = User::query()->create([
            'name' => 'Publisher', 'email' => 'publisher@example.test',
            'password' => 'CorrectHorse!234', 'role' => GatewayRole::Operator->value,
            'target_scope_mode' => 'selected', 'access_enabled' => true,
        ]);
        $site = Target::query()->create([
            'target_id' => 'demo-wp-publish', 'display_name' => 'Test WordPress',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => 'disconnected',
        ]);
        $group = TargetGroup::query()->create(['name' => 'Publisher group']);
        $group->users()->attach($publisher->id);
        $group->targets()->attach($site->id);

        return [$owner, $publisher, $group];
    }
}
