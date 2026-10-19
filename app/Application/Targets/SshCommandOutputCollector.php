<?php

namespace App\Application\Targets;

use phpseclib4\Net\SSH2;
use ReflectionException;
use ReflectionMethod;
use ReflectionProperty;
use RuntimeException;

/**
 * Bounded previews with complete, independent byte accounting.
 *
 * phpseclib4 SSH2::get_channel_packet() appends every extended-data packet
 * to the *private* stdErrorLog before forwarding its chunk to exec(callback).
 * getStdError() returns that cumulative log without clearing it. Simply
 * returning false from exec's callback would therefore still exhaust PHP
 * memory on verbose stderr, even if our own buffers were bounded.
 *
 * Clear the vendor stderr accumulator on EACH forwarded packet. Fail closed
 * on a vendor API mismatch instead of guessing stream provenance.
 */
final class SshCommandOutputCollector
{
    private readonly ReflectionProperty $stderrLog;

    private string $stdout = '';

    private string $stderr = '';

    private int $stdoutTotal = 0;

    private int $stderrTotal = 0;

    public function __construct(
        SSH2 $ssh,
        private readonly int $stdoutLimit,
        private readonly int $stderrLimit,
    ) {
        // Subclasses may override packet routing; only the exact inspected
        // phpseclib SSH2 implementation has the required callback contract.
        if ($ssh::class !== SSH2::class) {
            throw new RuntimeException('Unsupported SSH transport class for safe output draining.');
        }
        if ($stdoutLimit < 1 || $stderrLimit < 1 || $stdoutLimit > 524288 || $stderrLimit > 524288) {
            throw new RuntimeException('Invalid SSH capture budgets.');
        }
        try {
            $property = new ReflectionProperty(SSH2::class, 'stdErrorLog');
            $method = new ReflectionMethod(SSH2::class, 'getStdError');
            if (! $property->isPrivate() || (string) $property->getType() !== 'string'
                || $property->getDeclaringClass()->getName() !== SSH2::class
                || (string) $method->getReturnType() !== 'string'
                || $method->getDeclaringClass()->getName() !== SSH2::class) {
                throw new RuntimeException('Unsupported phpseclib stderr capture implementation.');
            }
            $this->stderrLog = $property;
        } catch (ReflectionException $exception) {
            throw new RuntimeException('Unsupported phpseclib stderr capture implementation.', 0, $exception);
        }
    }

    public function observe(SSH2 $ssh, string $chunk): void
    {
        // A retained vendor log is NEVER allowed to grow for the duration of
        // a command. packet-by-packet collection is the only approved mode.
        $pending = $this->stderrLog->getValue($ssh);
        if (! is_string($pending)) {
            throw new RuntimeException('SSH stderr buffer has an invalid type.');
        }
        if ($pending !== '') {
            $this->stderrLog->setValue($ssh, '');
            if (! hash_equals($pending, $chunk)) {
                throw new RuntimeException('SSH stream classification is ambiguous.');
            }
            $this->append($chunk, false);
        } else {
            $this->append($chunk, true);
        }
    }

    private function append(string $chunk, bool $isStdout): void
    {
        $length = strlen($chunk);
        if ($isStdout) {
            $this->stdoutTotal += $length;
            $this->stdout .= substr($chunk, 0, max(0, $this->stdoutLimit - strlen($this->stdout)));
        } else {
            $this->stderrTotal += $length;
            $this->stderr .= substr($chunk, 0, max(0, $this->stderrLimit - strlen($this->stderr)));
        }
    }

    /** @return array<string,int|string|bool> */
    public function result(): array
    {
        return [
            'stdout' => $this->stdout,
            'stderr' => $this->stderr,
            'stdout_bytes' => strlen($this->stdout),
            'stderr_bytes' => strlen($this->stderr),
            'stdout_total_bytes' => $this->stdoutTotal,
            'stderr_total_bytes' => $this->stderrTotal,
            'stdout_truncated' => $this->stdoutTotal > $this->stdoutLimit,
            'stderr_truncated' => $this->stderrTotal > $this->stderrLimit,
        ];
    }
}
