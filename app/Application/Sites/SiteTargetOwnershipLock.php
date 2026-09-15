<?php

namespace App\Application\Sites;

use Closure;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use PDO;
use Throwable;

final class SiteTargetOwnershipLock
{
    private const ACQUIRE_TIMEOUT_SECONDS = 10;

    /**
     * Serialize acquisition of one canonical target across create and target-changing update.
     *
     * The production runtime is MySQL. A MySQL named lock is connection-scoped rather than
     * transaction-scoped, so it remains authoritative while SiteLifecycleLock opens and
     * commits its own transaction around a remote revocation and the target write.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    public function runForHash(string $targetHash, Closure $callback): mixed
    {
        $connection = DB::connection();
        if ($connection->getDriverName() !== 'mysql') {
            return $callback();
        }

        $pdo = $connection->getPdo();
        $lockName = $this->lockName($connection, $targetHash);
        $statement = $pdo->prepare('SELECT GET_LOCK(?, ?)');
        $statement->execute([$lockName, self::ACQUIRE_TIMEOUT_SECONDS]);
        if ((int) $statement->fetchColumn() !== 1) {
            throw new SiteConnectionException('target_busy', 'The canonical target is currently being changed by another operation.');
        }

        try {
            return $callback();
        } finally {
            $this->release($pdo, $lockName);
        }
    }

    private function lockName(Connection $connection, string $targetHash): string
    {
        $database = (string) $connection->getDatabaseName();

        return sprintf('mcpgt:%s:%s', substr(hash('sha256', $database), 0, 12), substr($targetHash, 0, 45));
    }

    private function release(PDO $pdo, string $lockName): void
    {
        try {
            $statement = $pdo->prepare('SELECT RELEASE_LOCK(?)');
            $statement->execute([$lockName]);
            $statement->fetchColumn();
        } catch (Throwable) {
            // A dropped MySQL connection releases its named locks automatically.
        }
    }
}
