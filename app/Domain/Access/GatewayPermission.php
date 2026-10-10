<?php

namespace App\Domain\Access;

enum GatewayPermission: string
{
    case DashboardView = 'dashboard.view';
    case GatewayConnectionView = 'gateway.connection.view';
    case TargetsView = 'targets.view';
    case TargetsCreate = 'targets.create';
    case TargetsUpdate = 'targets.update';
    case TargetsRemove = 'targets.remove';
    case TargetsConnect = 'targets.connect';
    case TargetsReconnect = 'targets.reconnect';
    case TargetsDisconnect = 'targets.disconnect';
    case TargetsTest = 'targets.test';
    case WordpressAbilitiesInspect = 'wordpress.abilities.inspect';
    case WordpressAbilitiesExecuteReadonly = 'wordpress.abilities.execute.readonly';
    case WordpressAbilitiesExecuteMutating = 'wordpress.abilities.execute.mutating';
    case WordpressAbilitiesExecuteDestructive = 'wordpress.abilities.execute.destructive';
    case WordpressAbilitiesExecuteUnclassified = 'wordpress.abilities.execute.unclassified';
    case AgentEnvironmentRead = 'agent.environment.read';
    case AgentCommandRun = 'agent.command.run';
    case AgentRootCommandRun = 'agent.root_command.run';
    case AgentJobStart = 'agent.job.start';
    case AgentJobRead = 'agent.job.read';
    case AgentJobStop = 'agent.job.stop';
    case AgentFileRead = 'agent.file.read';
    case AgentFileWrite = 'agent.file.write';
    case AgentBrowserSetup = 'agent.browser.setup';
    case AgentBrowserRun = 'agent.browser.run';
    case SshCommandRun = 'ssh.command.run';
    case SshFileRead = 'ssh.file.read';
    case SshFileWrite = 'ssh.file.write';
    case ActivityView = 'activity.view';
    case UsersView = 'users.view';
    case UsersManage = 'users.manage';
    case SecurityManage = 'security.manage';

    public function title(): string
    {
        return match ($this) {
            self::DashboardView => 'View dashboard',
            self::GatewayConnectionView => 'View Gateway connection info',
            self::TargetsView => 'View Targets',
            self::TargetsCreate => 'Add Targets',
            self::TargetsUpdate => 'Edit Target details',
            self::TargetsRemove => 'Remove Targets',
            self::TargetsConnect => 'Connect Targets',
            self::TargetsReconnect => 'Reconnect Targets',
            self::TargetsDisconnect => 'Disconnect Targets',
            self::TargetsTest => 'Test Target connections',
            self::WordpressAbilitiesInspect => 'Inspect WordPress abilities',
            self::WordpressAbilitiesExecuteReadonly => 'Run read-only abilities',
            self::WordpressAbilitiesExecuteMutating => 'Run mutating abilities',
            self::WordpressAbilitiesExecuteDestructive => 'Run destructive abilities',
            self::WordpressAbilitiesExecuteUnclassified => 'Run unclassified abilities',
            self::AgentEnvironmentRead => 'Read Agent environment',
            self::AgentCommandRun => 'Run Agent worker commands',
            self::AgentRootCommandRun => 'Run Agent root commands',
            self::AgentJobStart => 'Start Agent jobs',
            self::AgentJobRead => 'Read Agent job status and output',
            self::AgentJobStop => 'Stop Agent jobs',
            self::AgentFileRead => 'Read Agent files',
            self::AgentFileWrite => 'Write Agent files',
            self::AgentBrowserSetup => 'Set up Agent browser',
            self::AgentBrowserRun => 'Run Agent browser',
            self::SshCommandRun => 'Run SSH remote commands',
            self::SshFileRead => 'Read SSH remote files',
            self::SshFileWrite => 'Write SSH remote files',
            self::ActivityView => 'View activity',
            self::UsersView => 'View users',
            self::UsersManage => 'Manage users and Target groups',
            self::SecurityManage => 'Manage security settings (reserved)',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::DashboardView => 'Open the admin dashboard. Target counts and health still follow targets.view and the effective Target scope; recent activity also requires activity.view.',
            self::GatewayConnectionView => 'View the Gateway MCP endpoint and OAuth/client metadata. This is Gateway-wide and does not grant access to any Target.',
            self::TargetsView => 'List and open Targets inside the user\'s effective Target scope. It never makes an out-of-scope Target visible.',
            self::TargetsCreate => 'Add a new Target to the Gateway. This is Gateway-wide. If the creator uses Selected Target scope, the new Target is automatically added to that user\'s scope.',
            self::TargetsUpdate => 'Change only the display name of an in-scope Target when this permission is allowed. Target identity, connector type and WordPress endpoint remain immutable.',
            self::TargetsRemove => 'Remove any Target inside the user\'s effective Target scope when this permission is allowed for that Target. Creation ownership is not considered; it is not limited to Targets the user created.',
            self::TargetsConnect => 'Start OAuth authorization for any Target inside the user\'s effective Target scope when this permission is allowed for that Target.',
            self::TargetsReconnect => 'Replace/re-authorize the stored connection for any in-scope Target when this permission is allowed for that Target.',
            self::TargetsDisconnect => 'Disconnect any in-scope Target and finalize its stored credential lifecycle when this permission is allowed for that Target.',
            self::TargetsTest => 'Run connection/health checks for Targets inside the user\'s effective Target scope when this permission is allowed for those Targets.',
            self::WordpressAbilitiesInspect => 'Read the downstream ability catalog and schemas for Targets inside the user\'s effective Target scope.',
            self::WordpressAbilitiesExecuteReadonly => 'Execute downstream abilities classified as read-only on Targets inside the user\'s effective Target scope.',
            self::WordpressAbilitiesExecuteMutating => 'Execute downstream abilities classified as mutating but not destructive on Targets inside the user\'s effective Target scope.',
            self::WordpressAbilitiesExecuteDestructive => 'Execute downstream abilities classified as destructive on Targets inside the user\'s effective Target scope. This permission should remain unavailable unless destructive operations are intended.',
            self::WordpressAbilitiesExecuteUnclassified => 'Execute downstream abilities whose safety class cannot be determined. This is a separate high-trust fallback and is not implied by read-only or mutating execution.',
            self::AgentEnvironmentRead => 'Target-scoped read agent environment; requires explicit Gateway, Target and connector permissions.',
            self::AgentCommandRun => 'Target-scoped run agent worker commands; requires explicit Gateway, Target and connector permissions.',
            self::AgentRootCommandRun => 'Target-scoped run agent root commands; requires explicit Gateway, Target and connector permissions.',
            self::AgentJobStart => 'Target-scoped start agent jobs; requires explicit Gateway, Target and connector permissions.',
            self::AgentJobRead => 'Target-scoped read agent job status and output; requires explicit Gateway, Target and connector permissions.',
            self::AgentJobStop => 'Target-scoped stop agent jobs; requires explicit Gateway, Target and connector permissions.',
            self::AgentFileRead => 'Target-scoped read agent files; requires explicit Gateway, Target and connector permissions.',
            self::AgentFileWrite => 'Target-scoped write agent files; requires explicit Gateway, Target and connector permissions.',
            self::AgentBrowserSetup => 'Target-scoped set up agent browser; requires explicit Gateway, Target and connector permissions.',
            self::AgentBrowserRun => 'Target-scoped run agent browser; requires explicit Gateway, Target and connector permissions.',
            self::SshCommandRun => 'Target-scoped run ssh remote commands; requires explicit Gateway, Target and connector permissions.',
            self::SshFileRead => 'Target-scoped read ssh remote files; requires explicit Gateway, Target and connector permissions.',
            self::SshFileWrite => 'Target-scoped write ssh remote files; requires explicit Gateway, Target and connector permissions.',
            self::ActivityView => 'Open the activity feed. Non-owner results are constrained to Targets visible through targets.view and the effective Target scope; owners retain unrestricted recovery visibility.',
            self::UsersView => 'View local Gateway user accounts. This is Gateway-wide and does not itself allow changing access.',
            self::UsersManage => 'Create and edit Gateway users, per-Target access rules, Target groups, and group membership. This is Gateway-wide access administration.',
            self::SecurityManage => 'Reserved Gateway-wide security administration permission. No current admin screen performs a security.manage action directly.',
        };
    }

    public function scopeLabel(): string
    {
        return $this->isTargetScoped() ? 'Target-scoped' : 'Gateway-wide';
    }

    public function isTargetScoped(): bool
    {
        return in_array($this, self::targetScoped(), true);
    }

    /** @return list<self> */
    public static function targetScoped(): array
    {
        return [
            self::TargetsView,
            self::TargetsUpdate,
            self::TargetsRemove,
            self::TargetsConnect,
            self::TargetsReconnect,
            self::TargetsDisconnect,
            self::TargetsTest,
            self::WordpressAbilitiesInspect,
            self::WordpressAbilitiesExecuteReadonly,
            self::WordpressAbilitiesExecuteMutating,
            self::WordpressAbilitiesExecuteDestructive,
            self::WordpressAbilitiesExecuteUnclassified,
            self::AgentEnvironmentRead,
            self::AgentCommandRun,
            self::AgentRootCommandRun,
            self::AgentJobStart,
            self::AgentJobRead,
            self::AgentJobStop,
            self::AgentFileRead,
            self::AgentFileWrite,
            self::AgentBrowserSetup,
            self::AgentBrowserRun,
            self::SshCommandRun,
            self::SshFileRead,
            self::SshFileWrite,
        ];
    }
}
