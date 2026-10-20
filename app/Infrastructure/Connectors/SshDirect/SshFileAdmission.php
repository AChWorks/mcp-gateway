<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use Closure;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Throwable;

/** Target-isolated finite SFTP admission, separate from login and command quotas. */
final class SshFileAdmission
{
    public function run(string $targetRecordId, Closure $operation, ?int $operationDeadlineNs = null): mixed
    {
        $key = 'ssh-file:'.hash('sha256', $targetRecordId);
        try {
            // The historic 90s lease covers ordinary 55s SFTP operations.
            // An Owner-approved long stream must retain the SAME per-Target
            // serialization until its absolute deadline plus cleanup margin.
            $remaining = $operationDeadlineNs === null ? 0
                : max(0, (int) ceil(($operationDeadlineNs - hrtime(true)) / 1_000_000_000));
            if ($remaining > 3600) {
                throw new SshTargetConnectionException('invalid_input');
            }
            $leaseSeconds = $remaining <= 55 ? 90 : $remaining + 90;
            $lock = Cache::lock($key.':lease', $leaseSeconds);
            if (! $lock->get()) {
                throw new SshTargetConnectionException('connection_busy');
            }
        } catch (SshTargetConnectionException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new SshTargetConnectionException('admission_unavailable');
        }

        try {
            try {
                if (RateLimiter::tooManyAttempts($key.':rate', 30)) {
                    throw new SshTargetConnectionException('rate_limited');
                }
                RateLimiter::hit($key.':rate', 60);
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (Throwable) {
                throw new SshTargetConnectionException('admission_unavailable');
            }

            return $operation();
        } finally {
            try {
                $lock->release();
            } catch (Throwable) {
                // Lease will expire if cache connection is lost.
            }
        }
    }
}
