<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use Closure;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Throwable;

/** Separate command admission budget; login verification's limited rate is not a command quota. */
final class SshCommandAdmission
{
    public function run(string $targetRecordId, Closure $operation): mixed
    {
        $base = 'ssh-command:'.hash('sha256', $targetRecordId);
        try {
            // The lease exceeds the maximum connect, authentication and exec budget.
            $lock = Cache::lock($base.':lease', 60);
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
                if (RateLimiter::tooManyAttempts($base.':rate', 30)) {
                    throw new SshTargetConnectionException('rate_limited');
                }
                RateLimiter::hit($base.':rate', 60);
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
                // Finite lease expiry is fail-safe if a worker loses its cache connection.
            }
        }
    }
}
