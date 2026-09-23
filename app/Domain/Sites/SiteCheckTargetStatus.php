<?php

namespace App\Domain\Sites;

enum SiteCheckTargetStatus: string
{
    case Pending = 'pending';
    case Running = 'running';
    case Succeeded = 'succeeded';
    case Failed = 'failed';
    case AuthorizationBlocked = 'authorization_blocked';
    case Missing = 'missing';
    case Interrupted = 'interrupted';

    public function isTerminal(): bool
    {
        return ! in_array($this, [self::Pending, self::Running], true);
    }

    public function isRetryable(): bool
    {
        return in_array($this, [self::Failed, self::Interrupted], true);
    }
}
