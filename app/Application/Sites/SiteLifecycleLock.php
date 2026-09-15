<?php

namespace App\Application\Sites;

use App\Domain\Sites\Site;
use Closure;
use Illuminate\Support\Facades\DB;

final class SiteLifecycleLock
{
    /**
     * @template TResult
     *
     * @param  Closure(Site): TResult  $callback
     * @return TResult
     */
    public function run(Site $site, Closure $callback): mixed
    {
        return $this->runForId((string) $site->getKey(), $callback);
    }

    /**
     * Serialize one site's connection lifecycle on the durable site row.
     *
     * SiteConnectionException is deliberately re-thrown only after the transaction
     * commits so failure-state transitions made by the lifecycle operation persist.
     * Any unexpected exception still aborts and rolls back the transaction.
     *
     * @template TResult
     *
     * @param  Closure(Site): TResult  $callback
     * @return TResult
     */
    public function runForId(string $siteRecordId, Closure $callback): mixed
    {
        $result = null;
        $failure = null;

        DB::transaction(function () use ($siteRecordId, $callback, &$result, &$failure): void {
            $site = Site::query()->whereKey($siteRecordId)->lockForUpdate()->first();
            if (! $site instanceof Site) {
                throw new SiteConnectionException('site_not_found', 'The site no longer exists.');
            }

            try {
                $result = $callback($site);
            } catch (SiteConnectionException $exception) {
                $failure = $exception;
            }
        });

        if ($failure instanceof SiteConnectionException) {
            throw $failure;
        }

        return $result;
    }
}
