<?php

namespace App\Domain\Sites;

enum SiteCheckOperationStatus: string
{
    case Pending = 'pending';
    case Running = 'running';
    case Completed = 'completed';
}
