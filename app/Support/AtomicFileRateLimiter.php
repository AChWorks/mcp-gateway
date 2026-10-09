<?php

namespace App\Support;

use Illuminate\Cache\FileStore;
use Illuminate\Cache\RateLimiter;

/**
 * Laravel's FileStore::increment() is a get/put pair, so concurrent workers
 * can discard each other's hits. Keep the normal Laravel limiter semantics
 * while serializing only updates to the same counter on the default file cache.
 *
 * Other cache drivers retain Laravel's native counter implementation.
 */
final class AtomicFileRateLimiter extends RateLimiter
{
    public function increment($key, $decaySeconds = 60, $amount = 1)
    {
        $store = $this->cache->getStore();
        if (! $store instanceof FileStore) {
            return parent::increment($key, $decaySeconds, $amount);
        }

        // A per-counter lock avoids global serialization across users/clients.
        // If acquisition times out, fail closed rather than permit an uncounted
        // request; do not silently fall back to the racy native increment.
        $lockName = 'gateway:rate-increment:'.hash('sha256', $this->cleanRateLimiterKey($key));

        return $store->lock($lockName, 5)->block(3, function () use ($key, $decaySeconds, $amount): int {
            return parent::increment($key, $decaySeconds, $amount);
        });
    }
}
