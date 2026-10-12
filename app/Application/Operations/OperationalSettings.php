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
    // Single Owner-only allowlist, NOT a generic config/.env editor.
    // Ranges are provisional pending #153/#154 measurements. The 8 MiB
    // HTTP body guard, fixed OAuth recovery window and PHP host limits
    // remain separate immutable boundaries.
    private const SETTING_RANGES = [
        'wp_response_kib' => ['minimum' => 16, 'maximum' => 1024],
        'wp_readonly_response_kib' => ['minimum' => 16, 'maximum' => 2048],
        // WordPress Bridge's one-shot 60-second refresh-token recovery window
        // makes longer synchronous HTTP attempts unsafe to expose as a knob.
        // This is NOT a logical operation or streaming/job timeout.
        'wp_connect_timeout_seconds' => ['minimum' => 1, 'maximum' => 15],
        'wp_request_timeout_seconds' => ['minimum' => 2, 'maximum' => 30],
        // Distinct aggregate SFTP object and whole-transfer budgets (not MCP frames).
        'ssh_transfer_max_kib' => ['minimum' => 256, 'maximum' => 65536],
        'ssh_transfer_max_seconds' => ['minimum' => 5, 'maximum' => 40],
    ];

    /** @var array<string, int>|null */
    private ?array $cachedOverrides = null;

    /** @return array<string, array{minimum:int,maximum:int}> */
    public static function allowed(): array
    {
        return self::SETTING_RANGES;
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

    /** @return array{connect:int,request:int} */
    public function httpTimeoutsSeconds(): array
    {
        $overrides = $this->overrides();

        // Existing env/config installations retain their exact normalized
        // fallback, including before the first operational-settings migration.
        $connect = $overrides['wp_connect_timeout_seconds']
            ?? max(1, (int) config('bridge.http.connect_timeout_seconds', 2));
        $request = $overrides['wp_request_timeout_seconds']
            ?? max(1, (int) config('bridge.http.request_timeout_seconds', 5));

        return ['connect' => $connect, 'request' => max($connect, $request)];
    }

    /** @return array{max_bytes:int,max_seconds:int} */
    public function sshTransferLimits(): array
    {
        $overrides = $this->overrides();
        $configuredMax = min(67108864, max(1, (int) config('ssh.file_transfer.max_bytes', 8388608)));
        $configuredSeconds = min(40, max(1, (int) config('ssh.file_transfer.max_seconds', 30)));

        return [
            'max_bytes' => isset($overrides['ssh_transfer_max_kib'])
                ? $overrides['ssh_transfer_max_kib'] * 1024 : $configuredMax,
            'max_seconds' => $overrides['ssh_transfer_max_seconds'] ?? $configuredSeconds,
        ];
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
            'overrides' => $this->combineOverrides($record),
        ];
    }

    /**
     * The form submits every supported key; blank resets an override.
     *
     * @param  array<string, int|null>  $values
     */
    public function save(User $actor, array $values, int $expectedVersion): void
    {
        $keys = array_keys($values);
        $all = array_keys(self::SETTING_RANGES);
        // A caller on an existing four-field source still needs a safe
        // upgrade path. Preserve rather than erase the new SSH overrides.
        if ($keys !== $all && $keys !== array_slice($all, 0, 4)) {
            throw ValidationException::withMessages([
                'values' => 'The operational settings request has an unknown or missing field.',
            ]);
        }
        if ($keys !== $all) {
            $previous = $this->state()['overrides'];
            foreach (array_slice($all, 4) as $key) {
                $values[$key] = $previous[$key] ?? null;
            }
        }

        $next = [];
        foreach (self::SETTING_RANGES as $key => $range) {
            $value = $values[$key];
            if ($value === null) {
                continue;
            }
            if ($value < $range['minimum'] || $value > $range['maximum']) {
                throw ValidationException::withMessages([
                    'values.'.$key => 'The operational setting is outside its supported range.',
                ]);
            }
            $next[$key] = $value;
        }

        $connect = $next['wp_connect_timeout_seconds']
            ?? max(1, (int) config('bridge.http.connect_timeout_seconds', 2));
        $request = $next['wp_request_timeout_seconds']
            ?? max(1, (int) config('bridge.http.request_timeout_seconds', 5));
        // A previously supported .env configuration may have a connection
        // timeout greater than the request timeout: the existing HTTP client
        // normalized the whole deadline to the connect timeout. With *no*
        // Owner network overrides, preserve that behavior even when changing
        // only response budgets. A newly explicit override must instead be a
        // valid pair, never silently clamped to an unexpected effective value.
        $hasNetworkOverride = isset($next['wp_connect_timeout_seconds'])
            || isset($next['wp_request_timeout_seconds']);
        if ($hasNetworkOverride && $connect > $request) {
            throw ValidationException::withMessages([
                'values.wp_request_timeout_seconds' => 'The overall request timeout must be at least the connection timeout.',
            ]);
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
            if (! property_exists($record, 'wp_connect_timeout_seconds')
                || ! property_exists($record, 'wp_request_timeout_seconds')) {
                throw new RuntimeException('Network settings migration is missing.');
            }
            $old = $this->combineOverrides($record);
            if ($old === $next) {
                return;
            }
            $revision = (int) $record->version + 1;
            $now = now();
            DB::table('operational_settings')->where('id', 1)->update([
                // Older released Gateways only understand the two response
                // keys in this JSON. New timeout columns allow safe rollback
                // without making older versions reject the settings row.
                'overrides' => json_encode(array_intersect_key($next, array_flip([
                    'wp_response_kib', 'wp_readonly_response_kib',
                ])), JSON_THROW_ON_ERROR),
                'wp_connect_timeout_seconds' => $next['wp_connect_timeout_seconds'] ?? null,
                'wp_request_timeout_seconds' => $next['wp_request_timeout_seconds'] ?? null,
                'ssh_transfer_max_kib' => $next['ssh_transfer_max_kib'] ?? null,
                'ssh_transfer_max_seconds' => $next['ssh_transfer_max_seconds'] ?? null,
                'version' => $revision,
                'changed_by' => $actor->getKey(),
                'updated_at' => $now,
            ]);
            foreach (self::SETTING_RANGES as $key => $range) {
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
            $row = DB::table('operational_settings')->where('id', 1)->first();
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

        return $this->cachedOverrides = $this->combineOverrides($row);
    }

    /** @return array<string,int> */
    private function combineOverrides(object $record): array
    {
        $overrides = $this->decodeOverrides((string) $record->overrides);
        foreach (['wp_connect_timeout_seconds', 'wp_request_timeout_seconds',
            'ssh_transfer_max_kib', 'ssh_transfer_max_seconds'] as $key) {
            $value = $record->{$key} ?? null;
            if ($value === null) {
                continue;
            }
            if (! is_int($value) && (! is_string($value) || ! ctype_digit($value))) {
                throw new RuntimeException('Operational network setting has an invalid type.');
            }
            $value = (int) $value;
            if ($value < self::SETTING_RANGES[$key]['minimum']
                || $value > self::SETTING_RANGES[$key]['maximum']) {
                throw new RuntimeException('Operational network setting is out of range.');
            }
            $overrides[$key] = $value;
        }

        return $overrides;
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
            if (! is_string($key) || ! in_array($key, ['wp_response_kib', 'wp_readonly_response_kib'], true)
                || ! is_int($value)
                || $value < self::SETTING_RANGES[$key]['minimum']
                || $value > self::SETTING_RANGES[$key]['maximum']) {
                throw new RuntimeException('Operational settings state contains an unsupported value.');
            }
            $result[$key] = $value;
        }

        return $result;
    }
}
