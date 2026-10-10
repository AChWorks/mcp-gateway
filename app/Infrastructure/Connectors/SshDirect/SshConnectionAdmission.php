<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use Closure;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Throwable;

/**
 * Serializes SSH verification per Target across PHP workers and limits real
 * outbound authentication attempts. Authorization must happen before entry.
 */
final class SshConnectionAdmission
{
    public function run(string $targetRecordId, Closure $operation): mixed
    {
        try {
            $lock = Cache::lock($this->key('lease', $targetRecordId), $this->leaseSeconds());
            if (! $lock->get()) {
                throw new SshTargetConnectionException('connection_busy');
            }
        } catch (SshTargetConnectionException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new SshTargetConnectionException('admission_unavailable');
        }

        try {
            $rateKey = $this->key('rate', $targetRecordId);
            try {
                if (RateLimiter::tooManyAttempts($rateKey, $this->maxAttempts())) {
                    throw new SshTargetConnectionException('rate_limited');
                }

                // Count only attempts that actually own the per-Target lease.
                RateLimiter::hit($rateKey, $this->decaySeconds());
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (Throwable) {
                throw new SshTargetConnectionException('admission_unavailable');
            }

            return $operation();
        } finally {
            // A failed release must not turn an already-completed verification
            // into a false failure. The finite lease still self-expires.
            try {
                $lock->release();
            } catch (Throwable) {
                // Intentionally fail-safe through finite lease expiry.
            }
        }
    }

    private function maxAttempts(): int
    {
        return max(1, min(60, (int) config('ssh.verification.max_attempts_per_minute', 6)));
    }

    private function decaySeconds(): int
    {
        return max(10, min(3600, (int) config('ssh.verification.decay_seconds', 60)));
    }

    private function leaseSeconds(): int
    {
        // TCP connect is capped at 5s and SSH handshake/login at 8s. Keep a
        // safety margin while bounding crash recovery.
        return max(20, min(120, (int) config('ssh.verification.lease_seconds', 30)));
    }

    private function key(string $kind, string $targetRecordId): string
    {
        return 'ssh-login-verify:'.$kind.':'.hash('sha256', $targetRecordId);
    }
}
