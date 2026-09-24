<?php

namespace App\Domain\Access;

enum GatewayPermission: string
{
    case DashboardView = 'dashboard.view';
    case ConnectionView = 'connection.view';
    case SitesView = 'sites.view';
    case SitesCreate = 'sites.create';
    case SitesUpdate = 'sites.update';
    case SitesRemove = 'sites.remove';
    case ConnectionsConnect = 'connections.connect';
    case ConnectionsReconnect = 'connections.reconnect';
    case ConnectionsDisconnect = 'connections.disconnect';
    case ConnectionsTest = 'connections.test';
    case AbilitiesInspect = 'abilities.inspect';
    case AbilitiesExecuteReadonly = 'abilities.execute.readonly';
    case AbilitiesExecuteMutating = 'abilities.execute.mutating';
    case AbilitiesExecuteDestructive = 'abilities.execute.destructive';
    case AbilitiesExecuteUnclassified = 'abilities.execute.unclassified';
    case ActivityView = 'activity.view';
    case UsersView = 'users.view';
    case UsersManage = 'users.manage';
    case SecurityManage = 'security.manage';

    public function title(): string
    {
        return match ($this) {
            self::DashboardView => 'View dashboard',
            self::ConnectionView => 'View Gateway connection info',
            self::SitesView => 'View sites',
            self::SitesCreate => 'Add sites',
            self::SitesUpdate => 'Edit site details',
            self::SitesRemove => 'Remove sites',
            self::ConnectionsConnect => 'Connect sites',
            self::ConnectionsReconnect => 'Reconnect sites',
            self::ConnectionsDisconnect => 'Disconnect sites',
            self::ConnectionsTest => 'Test site connections',
            self::AbilitiesInspect => 'Inspect site abilities',
            self::AbilitiesExecuteReadonly => 'Run read-only abilities',
            self::AbilitiesExecuteMutating => 'Run mutating abilities',
            self::AbilitiesExecuteDestructive => 'Run destructive abilities',
            self::AbilitiesExecuteUnclassified => 'Run unclassified abilities',
            self::ActivityView => 'View activity',
            self::UsersView => 'View users',
            self::UsersManage => 'Manage users and site groups',
            self::SecurityManage => 'Manage security settings (reserved)',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::DashboardView => 'Open the admin dashboard. Site counts and health still follow sites.view and the effective site scope; recent activity also requires activity.view.',
            self::ConnectionView => 'View the Gateway MCP endpoint and OAuth/client metadata. This is Gateway-wide and does not grant access to any site.',
            self::SitesView => 'List and open sites inside the user\'s effective site scope. It never makes an out-of-scope site visible.',
            self::SitesCreate => 'Add a new site to the Gateway. This is Gateway-wide. If the creator uses Selected site scope, the new site is automatically added to that user\'s scope.',
            self::SitesUpdate => 'Change the name or WordPress URL of any site inside the user\'s effective site scope when this permission is allowed for that site.',
            self::SitesRemove => 'Remove any site inside the user\'s effective site scope when this permission is allowed for that site. Creation ownership is not considered; it is not limited to sites the user created.',
            self::ConnectionsConnect => 'Start OAuth authorization for any site inside the user\'s effective site scope when this permission is allowed for that site.',
            self::ConnectionsReconnect => 'Replace/re-authorize the stored connection for any in-scope site when this permission is allowed for that site.',
            self::ConnectionsDisconnect => 'Disconnect any in-scope site and finalize its stored credential lifecycle when this permission is allowed for that site.',
            self::ConnectionsTest => 'Run connection/health checks for sites inside the user\'s effective site scope when this permission is allowed for those sites.',
            self::AbilitiesInspect => 'Read the downstream ability catalog and schemas for sites inside the user\'s effective site scope.',
            self::AbilitiesExecuteReadonly => 'Execute downstream abilities classified as read-only on sites inside the user\'s effective site scope.',
            self::AbilitiesExecuteMutating => 'Execute downstream abilities classified as mutating but not destructive on sites inside the user\'s effective site scope.',
            self::AbilitiesExecuteDestructive => 'Execute downstream abilities classified as destructive on sites inside the user\'s effective site scope. Grant this only when destructive operations are intended.',
            self::AbilitiesExecuteUnclassified => 'Execute downstream abilities whose safety class cannot be determined. This is a separate high-trust fallback and is not implied by read-only or mutating execution.',
            self::ActivityView => 'Open the activity feed. Non-owner results are constrained to sites visible through sites.view and the effective site scope; owners retain unrestricted recovery visibility.',
            self::UsersView => 'View local Gateway user accounts. This is Gateway-wide and does not itself allow changing access.',
            self::UsersManage => 'Create and edit Gateway users, per-site access rules, site groups, and group membership. This is Gateway-wide access administration.',
            self::SecurityManage => 'Reserved Gateway-wide security administration permission. No current admin screen performs a security.manage action directly.',
        };
    }

    public function scopeLabel(): string
    {
        return $this->isSiteScoped() ? 'Site-scoped' : 'Gateway-wide';
    }

    public function isSiteScoped(): bool
    {
        return in_array($this, self::siteScoped(), true);
    }

    /** @return list<self> */
    public static function siteScoped(): array
    {
        return [
            self::SitesView,
            self::SitesUpdate,
            self::SitesRemove,
            self::ConnectionsConnect,
            self::ConnectionsReconnect,
            self::ConnectionsDisconnect,
            self::ConnectionsTest,
            self::AbilitiesInspect,
            self::AbilitiesExecuteReadonly,
            self::AbilitiesExecuteMutating,
            self::AbilitiesExecuteDestructive,
            self::AbilitiesExecuteUnclassified,
        ];
    }
}
