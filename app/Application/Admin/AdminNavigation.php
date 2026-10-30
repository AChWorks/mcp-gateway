<?php

namespace App\Application\Admin;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Models\User;
use Illuminate\Support\Facades\Gate;

/** Shared navigation metadata; the existing Gates remain the authorization authority. */
final class AdminNavigation
{
    /** @var list<array{id:string,label:string,items:list<array{destination:string,activePattern:string,label:string,icon:string,permission:?GatewayPermission}>}> */
    private const SECTIONS = [
        ['id' => 'workspace', 'label' => 'Workspace', 'items' => [
            ['destination' => 'admin.dashboard', 'activePattern' => 'admin.dashboard', 'label' => 'Dashboard', 'icon' => 'dashboard', 'permission' => GatewayPermission::DashboardView],
            ['destination' => 'admin.targets.index', 'activePattern' => 'admin.targets.*', 'label' => 'Targets', 'icon' => 'targets', 'permission' => GatewayPermission::TargetsView],
            ['destination' => 'admin.activity', 'activePattern' => 'admin.activity', 'label' => 'Activity', 'icon' => 'activity', 'permission' => GatewayPermission::ActivityView],
        ]],
        ['id' => 'access', 'label' => 'Access', 'items' => [
            ['destination' => 'admin.users.index', 'activePattern' => 'admin.users.*', 'label' => 'Users', 'icon' => 'users', 'permission' => GatewayPermission::UsersView],
            ['destination' => 'admin.target-groups.index', 'activePattern' => 'admin.target-groups.*', 'label' => 'Target groups', 'icon' => 'groups', 'permission' => GatewayPermission::UsersManage],
            ['destination' => 'admin.oauth-clients.index', 'activePattern' => 'admin.oauth-clients.*', 'label' => 'AI clients', 'icon' => 'clients', 'permission' => GatewayPermission::SecurityManage],
        ]],
        ['id' => 'system', 'label' => 'System', 'items' => [
            ['destination' => 'admin.connection', 'activePattern' => 'admin.connection', 'label' => 'Connection information', 'icon' => 'connection', 'permission' => GatewayPermission::GatewayConnectionView],
            // Operations has always been Owner-only, independently of menu permissions.
            ['destination' => 'admin.operations.index', 'activePattern' => 'admin.operations.*', 'label' => 'Operational settings', 'icon' => 'settings', 'permission' => null],
        ]],
    ];

    /** @return list<array{id:string,label:string,items:list<array{destination:string,activePattern:string,label:string,icon:string}>}> */
    public function sections(User $user): array
    {
        if (! $user->access_enabled) {
            return [];
        }

        $sections = [];
        foreach (self::SECTIONS as $section) {
            $items = [];
            foreach ($section['items'] as $item) {
                if ($this->allowed($user, $item['permission'])) {
                    $items[] = [
                        'destination' => $item['destination'], 'activePattern' => $item['activePattern'],
                        'label' => __($item['label']), 'icon' => $item['icon'],
                    ];
                }
            }
            if ($items !== []) {
                $sections[] = ['id' => $section['id'], 'label' => __($section['label']), 'items' => $items];
            }
        }

        return $sections;
    }

    public function landingUrl(User $user): string
    {
        if ($user->access_enabled) {
            foreach (self::SECTIONS as $section) {
                foreach ($section['items'] as $item) {
                    if ($this->allowed($user, $item['permission'])) {
                        return route($item['destination']);
                    }
                }
            }
        }

        return route('admin.access');
    }

    /** Only known sidebar index routes are evaluated here, never resource-specific policy. */
    public function isDeniedIndexPath(User $user, string $path): bool
    {
        foreach (self::SECTIONS as $section) {
            foreach ($section['items'] as $item) {
                if (rtrim($path, '/') === rtrim(route($item['destination'], absolute: false), '/')) {
                    return ! $user->access_enabled || ! $this->allowed($user, $item['permission']);
                }
            }
        }

        return false;
    }

    private function allowed(User $user, ?GatewayPermission $permission): bool
    {
        return $permission === null
            ? $user->getAttribute('role') === GatewayRole::Owner
            : Gate::forUser($user)->allows($permission->value);
    }
}
