<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Latest observation of each independent connector check, not a health gate.
 * Mutators run under the existing Target row lock, never across remote I/O.
 */
final class TargetCheckEvidence
{
    public const SSH_LOGIN = 'ssh_login';

    public const WORDPRESS_METADATA = 'wordpress_metadata';

    public const ARVAN_HTTPS = 'arvan_https';

    public const ARVAN_AUTH = 'arvan_auth';

    private static function slot(Target $target, string $kind): Builder
    {
        return DB::table('target_check_evidence')->where('target_record_id', $target->getKey())->where('kind', $kind);
    }

    public static function beginLocked(Target $target, string $kind): string
    {
        $attempt = (string) Str::ulid();
        DB::table('target_check_evidence')->upsert([
            ['target_record_id' => $target->getKey(), 'kind' => $kind, 'attempt_id' => $attempt],
        ], ['target_record_id', 'kind'], ['attempt_id']);

        return $attempt;
    }

    public static function isCurrentLocked(Target $snapshot, Target $locked, string $kind, string $attempt): bool
    {
        return (int) $snapshot->transport_revision === (int) $locked->transport_revision
            && $snapshot->getKey() === $locked->getKey()
            && self::slot($locked, $kind)->where('attempt_id', $attempt)->exists();
    }

    public static function invalidateLocked(Target $target, string $kind): void
    {
        self::slot($target, $kind)->update(['transport_revision' => null, 'attempt_id' => null]);
    }

    public static function recordLocked(Target $target, string $kind, ?string $reason = null): void
    {
        $reason = $reason === null ? null : (preg_match('/^[a-z0-9_]{1,64}$/D', $reason) === 1 ? $reason : 'check_failed');
        $now = now()->format('Y-m-d H:i:s.u');
        $fields = [
            'transport_revision' => $target->transport_revision,
            'attempt_id' => null,
            'observed_at' => $now,
            'error_code' => $reason,
        ];
        if ($reason !== null) {
            $fields['last_failure_at'] = $now;
            $fields['last_failure_code'] = $reason;
        }
        DB::table('target_check_evidence')->upsert([
            ['target_record_id' => $target->getKey(), 'kind' => $kind, ...$fields],
        ], ['target_record_id', 'kind'], array_keys($fields));
    }

    public static function currentFailures(): Builder
    {
        return DB::table('target_check_evidence')->selectRaw('1')
            ->whereColumn('target_record_id', 'targets.id')
            ->whereColumn('transport_revision', 'targets.transport_revision')
            ->whereNotNull('observed_at')->whereNotNull('error_code');
    }
}
