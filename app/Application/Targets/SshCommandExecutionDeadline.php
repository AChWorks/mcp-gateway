<?php

namespace App\Application\Targets;

use Closure;
use InvalidArgumentException;
use RuntimeException;

/**
 * Whole-exec monotonic budget. phpseclib's socket timeout accounts for blocking
 * reads, not time spent delivering and processing a continuous packet stream.
 */
final class SshCommandExecutionDeadline
{
    /** @var Closure():int */
    private readonly Closure $clock;

    private readonly int $expiresAtNs;

    /** @param (Closure():int)|null $clock Injected only for deterministic clock tests. */
    public function __construct(int $seconds, ?Closure $clock = null)
    {
        if ($seconds < 1 || $seconds > 600) {
            throw new InvalidArgumentException('Invalid SSH command execution budget.');
        }

        $this->clock = $clock ?? static fn (): int => hrtime(true);
        $this->expiresAtNs = ($this->clock)() + $seconds * 1_000_000_000;
    }

    /**
     * Clamp the next vendor socket read to remaining *wall-clock* time.
     * phpseclib accepts only whole seconds; round up by less than 1 second.
     * The admission lease has a separate 90-second setup/cleanup margin.
     */
    public function remainingSocketSeconds(): int
    {
        $remainingNs = $this->expiresAtNs - ($this->clock)();
        if ($remainingNs <= 0) {
            throw new RuntimeException('SSH command monotonic execution deadline reached.');
        }

        return max(1, (int) ceil($remainingNs / 1_000_000_000));
    }

    public function expired(): bool
    {
        return ($this->clock)() >= $this->expiresAtNs;
    }
}
