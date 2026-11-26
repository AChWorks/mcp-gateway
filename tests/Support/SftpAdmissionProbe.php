<?php

namespace Tests\Support;

use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshExecutionAdmission;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionService;
use Illuminate\Database\Events\QueryExecuted;

/** Distinguish the shared admission reads of an actual SFTP operation from command/control reads. */
final class SftpAdmissionProbe
{
    // Pre-login, post-login, pre-staging, then immediately before payload.
    // The native tests also prove the actual zero-byte private inode at this fence.
    public const PRE_PAYLOAD_FENCE = 4;

    public static function readsCredential(QueryExecuted $query, string $credentialId): bool
    {
        $sql = str_replace(['"', chr(96)], '', strtolower($query->sql));
        if (! str_contains($sql, 'from target_credentials where target_credentials.id = ?')
            || (string) ($query->bindings[0] ?? '') !== $credentialId) {
            return false;
        }

        $admission = false;
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
            $class = $frame['class'] ?? null;
            if ($class === SshExecutionAdmission::class) {
                $admission = true;
            }
            // The nearest runtime owns the read, including nested proof
            // commands and reverification triggered by the query listener.
            if (in_array($class, [SshCommandRuntime::class, SshFileRuntime::class, SshTargetConnectionService::class], true)) {
                return $admission && $class === SshFileRuntime::class;
            }
        }

        return false;
    }
}
