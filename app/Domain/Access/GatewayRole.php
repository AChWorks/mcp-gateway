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
                GatewayPermission::GatewayConnectionView,
                GatewayPermission::TargetsView,
                GatewayPermission::TargetsCreate,
                GatewayPermission::TargetsUpdate,
                GatewayPermission::TargetsRemove,
                GatewayPermission::TargetsConnect,
                GatewayPermission::TargetsReconnect,
                GatewayPermission::TargetsDisconnect,
                GatewayPermission::TargetsTest,
                GatewayPermission::WordpressAbilitiesInspect,
                GatewayPermission::WordpressAbilitiesExecuteReadonly,
                GatewayPermission::WordpressAbilitiesExecuteMutating,
                GatewayPermission::WordpressAbilitiesExecuteDestructive,
                GatewayPermission::WordpressAbilitiesExecuteUnclassified,
                GatewayPermission::AgentEnvironmentRead,
                GatewayPermission::AgentCommandRun,
                GatewayPermission::AgentRootCommandRun,
                GatewayPermission::AgentJobStart,
                GatewayPermission::AgentJobRead,
                GatewayPermission::AgentJobStop,
                GatewayPermission::AgentFileRead,
                GatewayPermission::AgentFileWrite,
                GatewayPermission::AgentBrowserSetup,
                GatewayPermission::AgentBrowserRun,
                GatewayPermission::SshCommandRun,
                GatewayPermission::SshFileRead,
                GatewayPermission::SshFileWrite,
                GatewayPermission::ActivityView,
            ],
            self::Operator => [
                GatewayPermission::DashboardView,
                GatewayPermission::GatewayConnectionView,
                GatewayPermission::TargetsView,
                GatewayPermission::TargetsTest,
                GatewayPermission::WordpressAbilitiesInspect,
                GatewayPermission::WordpressAbilitiesExecuteReadonly,
                GatewayPermission::WordpressAbilitiesExecuteMutating,
                GatewayPermission::AgentEnvironmentRead,
                GatewayPermission::AgentCommandRun,
                GatewayPermission::SshCommandRun,
                GatewayPermission::SshFileRead,
                GatewayPermission::SshFileWrite,
                GatewayPermission::ActivityView,
            ],
            self::Viewer => [
                GatewayPermission::DashboardView,
                GatewayPermission::GatewayConnectionView,
                GatewayPermission::TargetsView,
                GatewayPermission::WordpressAbilitiesInspect,
                GatewayPermission::WordpressAbilitiesExecuteReadonly,
                GatewayPermission::AgentEnvironmentRead,
                GatewayPermission::ActivityView,
            ],
        };
    }

    public function allows(GatewayPermission $permission): bool
    {
        return in_array($permission, $this->permissions(), true);
    }
}
