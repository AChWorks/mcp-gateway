<?php

/** Explicit local-only grouping fixture. Called only by its retained browser case. */
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

if (! app()->environment('local') || getenv('GATEWAY_BROWSER_FIXTURE') !== '1'
    || getenv('GATEWAY_ADMIN_EXPERIENCE_FIXTURE') !== '1'
    || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    throw new RuntimeException('Grouping fixtures require the explicit isolated loopback environment.');
}

Route::middleware('web')->get('/__browser__/group-workflows/{role}', static function (string $role) {
    abort_unless(in_array($role, ['owner', 'operator'], true), 404);
    $users = [];
    foreach ([
        'owner' => ['Group browser owner', 'owner'],
        'operator' => ['Group browser operator', 'operator'],
        'member' => ['Group browser member', 'operator'],
        'other' => ['Group browser other member', 'viewer'],
    ] as $key => [$name, $gatewayRole]) {
        $users[$key] = User::query()->firstOrCreate(['email' => 'group-browser-'.$key.'@example.test'], [
            'name' => $name, 'password' => 'Group-Browser-Password!234',
            'role' => $gatewayRole, 'target_scope_mode' => $key === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ]);
        if ($key !== 'owner') {
            foreach (['ssh.command.run', 'ssh.file.read', 'ssh.file.write'] as $permission) {
                DB::table('user_permission_denials')->updateOrInsert([
                    'user_id' => $users[$key]->getKey(), 'permission' => $permission,
                ], ['created_at' => now(), 'updated_at' => now()]);
            }
        }
    }
    $targets = [];
    for ($index = 0; $index < 55; $index++) {
        $target = Target::query()->firstOrCreate(['target_id' => sprintf('group-browser-%03d', $index)], [
            'display_name' => sprintf('Group fixture Target %03d', $index),
            'connector_type' => 'wp_ai_bridge', 'connection_state' => TargetConnectionState::Disconnected,
        ]);
        $targets[] = ['id' => (string) $target->getKey(), 'target_id' => $target->target_id, 'label' => $target->display_name];
    }
    $special = [];
    foreach ([
        'native' => ['Group fixture native member', 'wp_ai_bridge'],
        'denial' => ['Group fixture denial member', 'wp_ai_bridge'],
        'ssh' => ['Group fixture SSH member', 'ssh_direct'],
        'blocked' => ['Group fixture explicitly blocked', 'wp_ai_bridge'],
    ] as $key => [$name, $connector]) {
        $special[$key] = Target::query()->firstOrCreate(['target_id' => 'group-browser-'.$key], [
            'display_name' => $name, 'connector_type' => $connector,
            'connection_state' => TargetConnectionState::Disconnected,
        ]);
    }
    $groups = [];
    foreach (['native' => 'Browser fixture native group', 'ssh' => 'Browser fixture SSH group', 'denial' => 'Browser fixture SSH-denial group'] as $key => $name) {
        $groups[$key] = TargetGroup::query()->firstOrCreate(['name' => $name]);
        $groups[$key]->targets()->syncWithoutDetaching([$special[$key]->getKey()]);
    }
    DB::table('target_group_permission_denials')->updateOrInsert([
        'target_group_id' => $groups['denial']->getKey(), 'permission' => 'ssh.file.read',
    ], ['created_at' => now(), 'updated_at' => now()]);
    DB::table('user_target_access')->updateOrInsert([
        'user_id' => $users['member']->getKey(), 'target_record_id' => $special['blocked']->getKey(),
    ], ['allowed' => false, 'created_at' => now(), 'updated_at' => now()]);
    Auth::login($users[$role]);

    return response()->json([
        'users' => array_map(static fn (User $user): array => ['id' => (string) $user->getKey(), 'label' => $user->name], $users),
        'groups' => array_map(static fn (TargetGroup $group): array => ['id' => (string) $group->getKey(), 'label' => $group->name], $groups),
        'targets' => $targets,
        'special' => array_map(static fn (Target $target): array => ['id' => (string) $target->getKey(), 'label' => $target->display_name], $special),
    ]);
});
