<?php

namespace App\Domain\Access;

enum SiteScopeMode: string
{
    case All = 'all';
    case Selected = 'selected';

    public function title(): string
    {
        return match ($this) {
            self::All => 'All sites',
            self::Selected => 'Selected sites',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::All => 'The user can reach every site unless a direct site deny excludes a target. Permission denials can still narrow capabilities.',
            self::Selected => 'The user can reach only directly allowed sites and sites supplied by assigned groups. A direct site deny always wins.',
        };
    }
}
