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
    public function run(string $targetRecordId, Closure $operation): mixed
    {
        $key = 'ssh-file:'.hash('sha256', $targetRecordId);
        try {
            $lock = Cache::lock($key.':lease', 90);
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
