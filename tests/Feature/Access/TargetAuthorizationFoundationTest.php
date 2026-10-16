<?php

namespace Tests\Feature\Access;

use App\Application\Access\AccessControl;
use App\Application\Access\TargetGroupManager;
use App\Application\Access\UserAccessManager;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Activity\ActivityFeed;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetAuthorizationFoundationTest extends TestCase
{
    use RefreshDatabase;

    public function test_new_nonowner_defaults_deny_ssh_and_only_supported_connector_types(): void
    {
        $manager = app(UserAccessManager::class);
        $administrator = $manager->create($this->attributes('administrator'), []);
        $operator = $manager->create($this->attributes('operator'), []);
        $viewer = $manager->create($this->attributes('viewer'), []);

        $denials = static fn (User $user): array => DB::table('user_permission_denials')
            ->where('user_id', $user->id)->pluck('permission')->all();

        foreach ([$administrator, $operator] as $user) {
            foreach (['ssh.command.run', 'ssh.file.read', 'ssh.file.write'] as $permission) {
                self::assertContains($permission, $denials($user));
            }
        }

        foreach ([$administrator, $operator, $viewer] as $user) {
            self::assertSame([], array_values(array_filter($denials($user),
                static fn (string $value): bool => str_starts_with($value, 'agent.'))));
        }

        self::assertSame(['wp_ai_bridge', 'ssh_direct'], Target::KNOWN_CONNECTOR_TYPES);
    }

    public function test_unrelated_user_edit_preserves_unrecognized_denials_without_enabling_them(): void
    {
        $manager = app(UserAccessManager::class);
        $user = $manager->create($this->attributes('administrator'), []);
        DB::table('user_permission_denials')->insert([
            'user_id' => $user->id,
            'permission' => 'unrecognized.extension.command.run',
        ]);

        $attributes = $this->attributes('administrator');
        $attributes['name'] = 'Renamed operator';
        $manager->update($user, $attributes, []);

        $denied = $manager->globalDenials($user->fresh());
        self::assertContains('ssh.command.run', $denied);
        self::assertContains('unrecognized.extension.command.run', $denied);
        self::assertSame('Renamed operator', $user->fresh()->name);
        self::assertNull(GatewayPermission::tryFrom('unrecognized.extension.command.run'));
    }

    public function test_unrecognized_denials_remain_inert_and_survive_target_and_group_edits(): void
    {
        $manager = app(UserAccessManager::class);
        $operator = $manager->create($this->attributes('operator'), []);
        $wp = $this->target('wordpress-site', 'wp_ai_bridge');
        $group = TargetGroup::query()->create(['name' => 'Restricted group']);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $wp->getKey(),
            'permission' => 'unrecognized.extension.command.run',
        ]);
        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(),
            'permission' => 'unrecognized.extension.file.read',
        ]);

        $manager->updateTargetRule($operator, $wp, 'allow',
            [GatewayPermission::WordpressAbilitiesInspect->value]);
        self::assertContains('unrecognized.extension.command.run', $manager->targetRule($operator, $wp)['denied_permissions']);
        self::assertContains(GatewayPermission::WordpressAbilitiesInspect->value,
            $manager->targetRule($operator, $wp)['denied_permissions']);

        app(TargetGroupManager::class)->update($group, 'Renamed group',
            [GatewayPermission::WordpressAbilitiesExecuteMutating->value]);
        self::assertContains('unrecognized.extension.file.read',
            app(TargetGroupManager::class)->permissionDenials($group));
        self::assertContains(GatewayPermission::WordpressAbilitiesExecuteMutating->value,
            app(TargetGroupManager::class)->permissionDenials($group));

        self::assertFalse(app(AccessControl::class)->allows(
            $operator, GatewayPermission::WordpressAbilitiesInspect, $wp));
        self::assertFalse(app(AccessControl::class)->allows(
            $operator, GatewayPermission::SshCommandRun, $wp));
    }

    public function test_selected_target_access_requires_membership_and_direct_deny_wins(): void
    {
        $user = app(UserAccessManager::class)->create($this->attributes('operator'), []);
        $target = $this->target('lab-one', 'ssh_direct');
        $access = app(AccessControl::class);

        self::assertFalse($access->allows($user, GatewayPermission::TargetsView, $target));
        self::assertSame(0, $access->scopeTargets(Target::query(), $user)->count());

        $group = TargetGroup::query()->create(['name' => 'Research']);
        $group->targets()->attach($target->getKey());
        $group->users()->attach($user->getKey());

        self::assertTrue($access->allows($user, GatewayPermission::TargetsView, $target));
        self::assertSame(1, $access->scopeTargets(Target::query(), $user)->count());
        self::assertFalse($access->allows($user, GatewayPermission::SshCommandRun, $target));

        DB::table('target_group_permission_denials')->insert([
            'target_group_id' => $group->getKey(),
            'permission' => GatewayPermission::TargetsView->value,
        ]);
        self::assertFalse($access->allows($user, GatewayPermission::TargetsView, $target));

        DB::table('target_group_permission_denials')->delete();
        DB::table('user_target_access')->insert([
            'user_id' => $user->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => false,
        ]);
        self::assertFalse($access->allows($user, GatewayPermission::TargetsView, $target));
    }

    public function test_activity_does_not_attribute_deleted_target_events_to_reused_public_slug(): void
    {
        $owner = app(UserAccessManager::class)->create($this->attributes('owner'), []);
        $operator = app(UserAccessManager::class)->create($this->attributes('operator'), []);
        $old = $this->target('repeatable-target', 'wp_ai_bridge');
        $recorder = app(ActivityRecorder::class);
        $recorder->recordRequired((string) Str::uuid(), 'target-test', 'success', $old);
        $oldRecordId = $old->getKey();
        $old->delete();

        $replacement = $this->target('repeatable-target', 'ssh_direct');
        $recorder->recordRequired((string) Str::uuid(), 'target-test', 'success', $replacement);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $replacement->getKey(),
            'allowed' => true,
        ]);

        $feed = app(ActivityFeed::class);
        $ownerEvents = $feed->page($owner, 1, 25, 'repeatable-target', 'target-test');
        $operatorEvents = $feed->page($operator, 1, 25, 'repeatable-target', 'target-test');

        self::assertCount(2, $ownerEvents['items']);
        self::assertCount(1, $operatorEvents['items']);
        self::assertSame($replacement->getKey(), $operatorEvents['items'][0]['target_record_id']);
        self::assertNotSame($oldRecordId, $operatorEvents['items'][0]['target_record_id']);
        self::assertSame('ssh_direct', $operatorEvents['items'][0]['connector_type_snapshot']);
    }

    public function test_activity_preserves_exact_oauth_client_profile_and_target_snapshot(): void
    {
        $owner = app(UserAccessManager::class)->create($this->attributes('owner'), []);
        $operator = app(UserAccessManager::class)->create($this->attributes('operator'), []);
        $target = $this->target('client-bound-target', 'wp_ai_bridge');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);

        $clientId = 'https://chatgpt.com/oauth/client.json';
        $request = app('request');
        $request->attributes->set('oauth_client_id', $clientId);
        $request->attributes->set('oauth_client_profile_key', 'chatgpt');
        $request->attributes->set('oauth_user_id', $operator->getKey());

        $recorder = app(ActivityRecorder::class);
        $recorder->recordRequired((string) Str::uuid(), 'client-target-audit', 'success', $target);

        $event = DB::table('activity_events')->where('operation', 'client-target-audit')->first();
        self::assertNotNull($event);
        self::assertSame('chatgpt', $event->client_profile_key);
        self::assertSame(hash('sha256', $clientId), $event->client_id_hash);
        self::assertSame($target->target_id, $event->target_id);
        self::assertSame($target->getKey(), $event->target_record_id);
        self::assertSame('wp_ai_bridge', $event->connector_type_snapshot);

        $feed = app(ActivityFeed::class);
        foreach ([$owner, $operator] as $viewer) {
            $items = $feed->page($viewer, 1, 25, $target->target_id, 'client-target-audit')['items'];
            self::assertCount(1, $items);
            self::assertSame('chatgpt', $items[0]['client_profile_key']);
            self::assertSame($target->getKey(), $items[0]['target_record_id']);
        }

        // A forged or malformed label is never persisted as an authenticated profile.
        $request->attributes->set('oauth_client_profile_key', '../injected');
        $recorder->recordRequired((string) Str::uuid(), 'invalid-client-label', 'success', $target);
        self::assertNull(DB::table('activity_events')
            ->where('operation', 'invalid-client-label')->value('client_profile_key'));
    }

    public function test_connector_scoped_permissions_cannot_authorize_another_connector_family(): void
    {
        $owner = app(UserAccessManager::class)->create($this->attributes('owner'), []);
        $wp = $this->target('blog-one', 'wp_ai_bridge');
        $ssh = $this->target('server-ssh', 'ssh_direct');
        $access = app(AccessControl::class);

        self::assertFalse($access->allows($owner, GatewayPermission::SshCommandRun, $wp));
        self::assertTrue($access->allows($owner, GatewayPermission::SshCommandRun, $ssh));

        self::assertSame(
            ['server-ssh'],
            $access->scopeTargets(Target::query(), $owner, GatewayPermission::SshCommandRun)
                ->pluck('target_id')->all(),
        );
    }

    public function test_ssh_permission_must_have_selected_scope_even_if_global_denial_is_removed(): void
    {
        $operator = app(UserAccessManager::class)->create($this->attributes('operator'), []);
        $target = $this->target('ssh-lab', 'ssh_direct');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);

        $access = app(AccessControl::class);
        self::assertFalse($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        // Represents an explicit Owner authorization. A global role ceiling alone is insufficient.
        DB::table('user_permission_denials')->where([
            'user_id' => $operator->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ])->delete();
        self::assertTrue($access->allows($operator, GatewayPermission::SshCommandRun, $target));

        $operator->forceFill(['target_scope_mode' => 'all'])->save();
        self::assertFalse($access->allows($operator->fresh(), GatewayPermission::SshCommandRun, $target));
    }

    /** @return array{name:string,email:string,password:string,role:string,target_scope_mode:string,access_enabled:bool} */
    private function attributes(string $role): array
    {
        return [
            'name' => 'Test '.$role,
            'email' => Str::random(12).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => $role === GatewayRole::Owner->value ? 'all' : 'selected',
            'access_enabled' => true,
        ];
    }

    private function target(string $id, string $type): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => 'Target '.$id,
            'connector_type' => $type,
        ]);
    }
}
