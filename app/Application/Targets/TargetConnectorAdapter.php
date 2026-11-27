<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Models\User;
use Closure;

interface TargetConnectorAdapter
{
    public function type(): string;

    /** @return array<string, array<int, mixed>> */
    public function registrationRules(): array;

    /** @param array<string, mixed> $input */
    public function register(array $input, ?User $creator = null, ?Closure $authorize = null): Target;

    /**
     * Connector-specific actor reauthentication. Selecting a Relay always
     * requires confirmation independently of this rule. An empty input
     * describes the default enrollment mode.
     *
     * @param  array<string,mixed>  $input
     */
    public function registrationRequiresPassword(array $input): bool;

    /** @return array<string, array<int, mixed>> */
    public function configurationRules(Target $target): array;

    public function configurationRevision(Target $target): string;

    /** @param array<string, mixed> $input */
    public function updateConfiguration(Target $target, array $input, ?Closure $authorize = null): TargetConnectorResult;

    public function connect(Target $target, ?Closure $authorize = null): TargetConnectorResult;

    public function reconnect(Target $target, ?Closure $authorize = null): TargetConnectorResult;

    public function disconnect(Target $target, ?Closure $authorize = null): TargetConnectorResult;

    public function test(Target $target, ?Closure $authorize = null): TargetConnectorResult;

    public function hasPendingDeletion(Target $target): bool;
}
