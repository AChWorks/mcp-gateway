<?php

namespace App\Domain\Access;

enum GatewayRole: string
{
    case Owner = 'owner';
    case Administrator = 'administrator';
    case Operator = 'operator';
    case Viewer = 'viewer';

    /** @return list<GatewayPermission> */
    public function permissions(): array
    {
        return match ($this) {
            self::Owner => GatewayPermission::cases(),
            self::Administrator => [
                GatewayPermission::DashboardView,
                GatewayPermission::ConnectionView,
                GatewayPermission::SitesView,
                GatewayPermission::SitesCreate,
                GatewayPermission::SitesUpdate,
                GatewayPermission::SitesRemove,
                GatewayPermission::ConnectionsConnect,
                GatewayPermission::ConnectionsReconnect,
                GatewayPermission::ConnectionsDisconnect,
                GatewayPermission::ConnectionsTest,
                GatewayPermission::AbilitiesInspect,
                GatewayPermission::AbilitiesExecuteReadonly,
                GatewayPermission::AbilitiesExecuteMutating,
                GatewayPermission::AbilitiesExecuteDestructive,
                GatewayPermission::AbilitiesExecuteUnclassified,
                GatewayPermission::ActivityView,
            ],
            self::Operator => [
                GatewayPermission::DashboardView,
                GatewayPermission::ConnectionView,
                GatewayPermission::SitesView,
                GatewayPermission::ConnectionsTest,
                GatewayPermission::AbilitiesInspect,
                GatewayPermission::AbilitiesExecuteReadonly,
                GatewayPermission::AbilitiesExecuteMutating,
                GatewayPermission::ActivityView,
            ],
            self::Viewer => [
                GatewayPermission::DashboardView,
                GatewayPermission::ConnectionView,
                GatewayPermission::SitesView,
                GatewayPermission::AbilitiesInspect,
                GatewayPermission::AbilitiesExecuteReadonly,
                GatewayPermission::ActivityView,
            ],
        };
    }

    public function allows(GatewayPermission $permission): bool
    {
        return in_array($permission, $this->permissions(), true);
    }
}
