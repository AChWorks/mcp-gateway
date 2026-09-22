<?php

namespace App\Domain\Access;

enum SiteScopeMode: string
{
    case All = 'all';
    case Selected = 'selected';
}
