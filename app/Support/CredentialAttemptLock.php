<?php

namespace App\Support;

use Closure;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Cache;
use RuntimeException;

final class CredentialAttemptLock
{
    /**
     * Serialize the check, password verification and failed-attempt hit for
     * one login identity or already-authenticated account. Per-IP throttles
     * alone cannot prevent simultaneous distributed credential guesses.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $attempt
     * @return TResult
     */
    public function run(string $identity, Closure $attempt): mixed
    {
        /** @var Repository $cache */
        $cache = Cache::store(config('cache.limiter'));
        $store = $cache->getStore();
        if (! $store instanceof LockProvider) {
            throw new RuntimeException('Credential attempt locking requires a shared lock-capable limiter cache.');
        }

        try {
            return $store->lock('gateway:credential-attempt:'.hash('sha256', $identity), 10)
                ->block(3, $attempt);
        } catch (LockTimeoutException) {
            throw new HttpResponseException(response('Too many concurrent authentication attempts. Retry shortly.', 429)
                ->header('Retry-After', '3')
                ->header('Cache-Control', 'no-store'));
        }
    }
}
