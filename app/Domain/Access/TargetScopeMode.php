<?php

namespace App\Domain\Access;

enum TargetScopeMode: string
{
    case All = 'all';
    case Selected = 'selected';

    public function title(): string
    {
        return match ($this) {
            self::All => 'All targets',
            self::Selected => 'Selected targets',
        };
    }

    public function description(): string
    {
        return match ($this) {
            self::All => 'The user can reach every target unless a direct target deny excludes a target. Permission denials can still narrow capabilities.',
            self::Selected => 'The user can reach only directly allowed targets and targets supplied by assigned groups. A direct target deny always wins.',
        };
    }
}
