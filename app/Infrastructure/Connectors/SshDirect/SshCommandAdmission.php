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
    public function run(string $targetRecordId, Closure $operation, int $execTimeoutSeconds = 30): mixed
    {
        $base = 'ssh-command:'.hash('sha256', $targetRecordId);
        try {
            // Lease spans bounded transport setup, the *admitted actual*
            // selected exec deadline, and cleanup margin. A fixed 90-second
            // lease would permit overlapping effectful calls after 90s.
            // Preserve the current lease for the default <=30-second path.
            if ($execTimeoutSeconds < 1 || $execTimeoutSeconds > 600) {
                throw new SshTargetConnectionException('invalid_input');
            }
            $lock = Cache::lock($base.':lease', $execTimeoutSeconds <= 30 ? 90 : $execTimeoutSeconds + 90);
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
