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
