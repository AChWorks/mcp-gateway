<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;

interface TargetConnectorAdapter
{
    public function type(): string;

    /** @return array<string, array<int, mixed>> */
    public function registrationRules(): array;

    /** @param array<string, mixed> $input */
    public function register(array $input): Target;

    public function registrationStatus(): string;

    public function connect(Target $target): TargetConnectorResult;

    public function reconnect(Target $target): TargetConnectorResult;

    public function disconnect(Target $target): TargetConnectorResult;

    public function test(Target $target): TargetConnectorResult;

    /** @return array<string, mixed> */
    public function adminDetails(Target $target): array;

    /** @return array<string, mixed> */
    public function publicMetadata(Target $target): array;

    public function hasPendingDeletion(Target $target): bool;
}
