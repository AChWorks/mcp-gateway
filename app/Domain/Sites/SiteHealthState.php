<?php

namespace App\Domain\Sites;

enum SiteHealthState: string
{
    case Healthy = 'healthy';
    case Stale = 'stale';
    case NeverConnected = 'never_connected';
    case Disconnected = 'disconnected';
    case ReconnectRequired = 'reconnect_required';
    case Unreachable = 'unreachable';
    case Incompatible = 'incompatible';
    case Failed = 'failed';
    case Pending = 'pending';
    case UpdatingTarget = 'updating_target';
    case Unknown = 'unknown';
}
