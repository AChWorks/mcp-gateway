<?php

namespace App\Domain\Access;

enum AbilityExecutionClass: string
{
    case Readonly = 'readonly';
    case Mutating = 'mutating';
    case Destructive = 'destructive';
    case Unclassified = 'unclassified';

    public function permission(): GatewayPermission
    {
        return match ($this) {
            self::Readonly => GatewayPermission::AbilitiesExecuteReadonly,
            self::Mutating => GatewayPermission::AbilitiesExecuteMutating,
            self::Destructive => GatewayPermission::AbilitiesExecuteDestructive,
            self::Unclassified => GatewayPermission::AbilitiesExecuteUnclassified,
        };
    }

    public function hasMutationRisk(): bool
    {
        return $this !== self::Readonly;
    }
}
