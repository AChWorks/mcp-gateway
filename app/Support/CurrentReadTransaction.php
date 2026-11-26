<?php

namespace App\Support;

use Closure;
use Illuminate\Support\Facades\DB;

/** Short local admission transactions, never holding locks across remote I/O. */
final class CurrentReadTransaction
{
    /**
     * Avoid a stale repeatable-read snapshot during final policy verification.
     * Scope isolation to this transaction, not the session or whole database.
     * Do not retry implicitly under a different isolation level.
     *
     * @template T
     *
     * @param  Closure():T  $operation
     * @return T
     */
    public static function run(Closure $operation): mixed
    {
        $connection = DB::connection();
        if (in_array($connection->getDriverName(), ['mysql', 'mariadb'], true)) {
            $connection->statement('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
        }

        return $connection->transaction($operation);
    }
}
