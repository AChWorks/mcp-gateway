<?php

namespace App\Application\Operations;

use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use JsonException;
use RuntimeException;

final class OperationalSettings
{
    // This is an allowlist, NOT a generic config/.env editor. Numeric
    // envelopes are deliberately provisional until #153/#154 host benchmarks.
    // The HTTP transport's 8 MiB absolute decoded-body guard still applies.
    private const RESPONSE_LIMITS = [
        'wp_response_kib' => ['minimum' => 16, 'maximum' => 1024],
        'wp_readonly_response_kib' => ['minimum' => 16, 'maximum' => 2048],
    ];

    /** @var array<string, int>|null */
    private ?array $cachedOverrides = null;

    /** @return array<string, array{minimum:int,maximum:int}> */
    public static function allowed(): array
    {
        return self::RESPONSE_LIMITS;
    }

    public function responseLimitBytes(bool $readOnly): int
    {
        $key = $readOnly ? 'wp_readonly_response_kib' : 'wp_response_kib';
        $overrides = $this->overrides();
        if (isset($overrides[$key])) {
            return $overrides[$key] * 1024;
        }

        // Preserve the exact legacy config/.env byte fallback, including
        // non-KiB-aligned values and the existing hard decoded body bound.
        return $readOnly
            ? (int) config('bridge.http.readonly_tool_max_response_bytes', 262144)
            : (int) config('bridge.http.max_response_bytes', 65536);
    }

    /** @return array{version:int,overrides:array<string,int>} */
    public function state(): array
    {
        // The Owner Admin surface requires the migration to exist; unlike a
        // pre-migration connection it cannot present a fictitious saved state.
        $record = DB::table('operational_settings')->where('id', 1)->first();
        if ($record === null) {
            throw new RuntimeException('Operational settings state is missing.');
        }

        return [
            'version' => (int) $record->version,
            'overrides' => $this->decodeOverrides((string) $record->overrides),
        ];
    }

    /**
     * The form submits every supported key; blank resets an override.
     *
     * @param  array<string, int|null>  $values
     */
    public function save(User $actor, array $values, int $expectedVersion): void
    {
        if (array_keys($values) !== array_keys(self::RESPONSE_LIMITS)) {
            throw ValidationException::withMessages([
                'values' => 'The operational settings request has an unknown or missing field.',
            ]);
        }

        $next = [];
        foreach (self::RESPONSE_LIMITS as $key => $range) {
            $value = $values[$key];
            if ($value === null) {
                continue;
            }
            if ($value < $range['minimum'] || $value > $range['maximum']) {
                throw ValidationException::withMessages([
                    'values.'.$key => 'The requested response budget is outside its supported range.',
                ]);
            }
            $next[$key] = $value;
        }

        DB::transaction(function () use ($actor, $expectedVersion, $next): void {
            // One row serializes simultaneous edits from Owner browser tabs.
            // The expected version rejects stale forms and lost updates.
            $record = DB::table('operational_settings')->where('id', 1)
                ->lockForUpdate()->first();
            if ($record === null || (int) $record->version !== $expectedVersion) {
                throw ValidationException::withMessages([
                    'version' => 'Operational settings changed. Reload the page before saving.',
                ]);
            }
            $old = $this->decodeOverrides((string) $record->overrides);
            if ($old === $next) {
                return;
            }
            $revision = (int) $record->version + 1;
            $now = now();
            DB::table('operational_settings')->where('id', 1)->update([
                'overrides' => json_encode($next, JSON_THROW_ON_ERROR),
                'version' => $revision,
                'changed_by' => $actor->getKey(),
                'updated_at' => $now,
            ]);
            foreach (self::RESPONSE_LIMITS as $key => $range) {
                $previous = $old[$key] ?? null;
                $updated = $next[$key] ?? null;
                if ($previous === $updated) {
                    continue;
                }
                DB::table('operational_setting_changes')->insert([
                    'id' => (string) Str::ulid(),
                    'setting_key' => $key,
                    'previous_value' => $previous,
                    'new_value' => $updated,
                    'version' => $revision,
                    'actor_user_id' => $actor->getKey(),
                    'created_at' => $now,
                ]);
            }
        });
        // Same-request callers (e.g. test harness) must observe the write;
        // other FPM/CLI requests have their own scoped instance.
        $this->cachedOverrides = $next;
    }

    /** @return array<string,int> */
    private function overrides(): array
    {
        if ($this->cachedOverrides !== null) {
            return $this->cachedOverrides;
        }
        try {
            $row = DB::table('operational_settings')->where('id', 1)->first(['overrides']);
        } catch (QueryException $exception) {
            // Existing bare HTTP and installer pre-migration paths must still
            // use their source-config defaults. Never swallow DB connectivity
            // errors or other queries from a migrated installation.
            $driverCode = $exception->errorInfo[1] ?? null;
            $isMysqlMissing = $driverCode === 1146;
            $isSqliteMissing = str_contains($exception->getMessage(), 'no such table: operational_settings');
            if (! $isMysqlMissing && ! $isSqliteMissing) {
                throw $exception;
            }

            return $this->cachedOverrides = [];
        }
        if ($row === null) {
            throw new RuntimeException('Operational settings state is missing.');
        }

        return $this->cachedOverrides = $this->decodeOverrides((string) $row->overrides);
    }

    /** @return array<string,int> */
    private function decodeOverrides(string $json): array
    {
        try {
            $values = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Operational settings state is not valid JSON.', 0, $exception);
        }
        if (! is_array($values)) {
            throw new RuntimeException('Operational settings state has an invalid shape.');
        }
        $result = [];
        foreach ($values as $key => $value) {
            if (! is_string($key) || ! isset(self::RESPONSE_LIMITS[$key])
                || ! is_int($value)
                || $value < self::RESPONSE_LIMITS[$key]['minimum']
                || $value > self::RESPONSE_LIMITS[$key]['maximum']) {
                throw new RuntimeException('Operational settings state contains an unsupported value.');
            }
            $result[$key] = $value;
        }

        return $result;
    }
}
