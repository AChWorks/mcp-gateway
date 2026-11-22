<?php

namespace App\Application\Batch;

use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use Closure;

/** Only reviewed built-in operations can enter the shared durable Batch Core. */
interface TargetBatchOperationProvider
{
    public function key(): string;

    public function connectorType(): string;

    public function permission(): GatewayPermission;

    public function isEffectful(): bool;

    /** @param array<string,mixed> $arguments */
    public function validArguments(array $arguments): bool;

    /**
     * Called after a durable, non-replayable dispatch claim. The provided
     * gate MUST run again as close to each new remote effect as possible.
     *
     * @param  array<string,mixed>  $arguments
     * @return array<string,mixed>
     */
    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess): array;
}
