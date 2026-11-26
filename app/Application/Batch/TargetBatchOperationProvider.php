<?php

namespace App\Application\Batch;

use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityAttribution;
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
     * Maximum expected operation duration before remote-effect outcome must
     * be reconciled as UNKNOWN after a lost worker. This is connector-owned:
     * the shared scheduler cannot know native SSH/HTTP/other timeouts.
     *
     * @param  array<string,mixed>  $arguments
     */
    public function remoteTimeoutSeconds(array $arguments): int;

    /**
     * The preflight guard checks current authority without claiming a send.
     * The final admission gate MUST succeed at each new protected transport
     * effect, after local preparation. It durably records possible dispatch.
     * Its connector verifier runs locally under the attempt lock (no I/O).
     * Attribution belongs to the originating actor/client, not the Worker.
     *
     * @param  Closure():bool  $beforeRemoteEffect
     * @param  Closure(Closure():void):bool  $admitRemoteEffect
     * @param  array<string,mixed>  $arguments
     * @return array<string,mixed>
     */
    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess, Closure $admitRemoteEffect, ActivityAttribution $attribution): array;
}
