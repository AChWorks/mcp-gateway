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
            self::Readonly => GatewayPermission::WordpressAbilitiesExecuteReadonly,
            self::Mutating => GatewayPermission::WordpressAbilitiesExecuteMutating,
            self::Destructive => GatewayPermission::WordpressAbilitiesExecuteDestructive,
            self::Unclassified => GatewayPermission::WordpressAbilitiesExecuteUnclassified,
        };
    }

    public function hasMutationRisk(): bool
    {
        return $this !== self::Readonly;
    }
}
