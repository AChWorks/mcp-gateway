<?php

namespace App\Domain\Sites;

enum SiteConnectionState: string
{
    case Disconnected = 'disconnected';
    case Pending = 'pending';
    case Connected = 'connected';
    case ReconnectRequired = 'reconnect_required';
    case Error = 'error';
}
