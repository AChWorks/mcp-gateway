<?php

namespace App\Domain\Targets;

enum TargetConnectionState: string
{
    case Disconnected = 'disconnected';
    case Pending = 'pending';
    case Connected = 'connected';
    case Reassigning = 'reassigning';
    case ReconnectRequired = 'reconnect_required';
    case Error = 'error';
}
