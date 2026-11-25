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
        'ssh_transfer_max_seconds' => ['minimum' => 5, 'maximum' => 3600],
        // Sync SSH commands remain bounded by PHP/proxy/transport limits.
        // Larger or slower scripts use the retained Direct SSH Job path.
        'ssh_command_timeout_seconds' => ['minimum' => 15, 'maximum' => 600],
        'ssh_command_max_kib' => ['minimum' => 8, 'maximum' => 512],
        // Detached jobs have independent, Owner-adjustable resource budgets.
        // The service retains uncertain identities even after admission ends.
        'ssh_job_max_active_per_user' => ['minimum' => 1, 'maximum' => 1024],
        'ssh_job_max_runtime_seconds' => ['minimum' => 300, 'maximum' => 604800],
        'ssh_job_retention_hours' => ['minimum' => 1, 'maximum' => 8760],
        'ssh_job_preparing_grace_seconds' => ['minimum' => 30, 'maximum' => 600],
        'ssh_job_reconcile_grace_seconds' => ['minimum' => 60, 'maximum' => 3600],
        'ssh_job_max_script_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_command_stdout_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_command_stderr_kib' => ['minimum' => 8, 'maximum' => 512],
        'ssh_job_output_window_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_file_read_window_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_file_write_window_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_file_list_name_kib' => ['minimum' => 16, 'maximum' => 512],
        // The Bridge whole JSON-RPC request limit and DCR capacity are separate.
        'wp_ability_input_kib' => ['minimum' => 16, 'maximum' => 4096],
        'dcr_registration_capacity' => ['minimum' => 16, 'maximum' => 65536],
        // Batch admission is not a limit on registered/selected Target counts.
        // These are independently tunable active and per-invocation budgets.
        'batch_max_parallelism' => ['minimum' => 1, 'maximum' => 65535],
        'batch_global_active' => ['minimum' => 1, 'maximum' => 65535],
        'batch_user_active' => ['minimum' => 1, 'maximum' => 65535],
        'batch_worker_max_children' => ['minimum' => 1, 'maximum' => 65535],
        'batch_worker_max_seconds' => ['minimum' => 1, 'maximum' => 86400],
    ];

    // These two settings are stored in the existing JSON column. Other
    // settings are typed database columns; both are active persisted data.
    private const JSON_KEYS = ['wp_response_kib', 'wp_readonly_response_kib'];

    /** @var array<string, int>|null */
    private ?array $cachedOverrides = null;

    /** @return array<string, array{minimum:int,maximum:int}> */
    public static function allowed(): array
    {
        return self::SETTING_RANGES;
    }

    /**
     * Any nonempty set of supported settings is valid. Omitted values
     * remain unchanged; an explicit null resets one override.
     *
     * @param  list<string>  $names
     */
    public static function acceptsFormKeys(array $names): bool
    {
        return $names !== [] && array_diff($names, array_keys(self::SETTING_RANGES)) === [];
    }

    /** @return list<string> */
    private static function columnKeys(): array
    {
        return array_values(array_diff(array_keys(self::SETTING_RANGES), self::JSON_KEYS));
    }

    /** @return array<string,int|float> */
    public function defaults(): array
    {
        $defaults = [];
        foreach (array_keys(self::SETTING_RANGES) as $key) {
            $defaults[$key] = $this->defaultValue($key);
        }
        $defaults['wp_request_timeout_seconds'] = max(
            $defaults['wp_connect_timeout_seconds'], $defaults['wp_request_timeout_seconds'],
        );

        return $defaults;
    }

    private function defaultValue(string $key): int|float
    {
        return match ($key) {
            'wp_response_kib' => (int) config('bridge.http.max_response_bytes', 65536) / 1024,
            'wp_readonly_response_kib' => (int) config('bridge.http.readonly_tool_max_response_bytes', 262144) / 1024,
            'wp_connect_timeout_seconds' => max(1, (int) config('bridge.http.connect_timeout_seconds', 2)),
            'wp_request_timeout_seconds' => max(1, (int) config('bridge.http.request_timeout_seconds', 5)),
            'ssh_transfer_max_kib' => min(67108864, max(1, (int) config('ssh.file_transfer.max_bytes', 8388608))) / 1024,
            'ssh_transfer_max_seconds' => min(3600, max(1, (int) config('ssh.file_transfer.max_seconds', 30))),
            'ssh_command_timeout_seconds' => 15,
            'ssh_command_max_kib' => 8,
            'ssh_job_max_active_per_user' => 2,
            'ssh_job_max_runtime_seconds' => 300,
            'ssh_job_retention_hours' => 24,
            'ssh_job_preparing_grace_seconds' => 120,
            'ssh_job_reconcile_grace_seconds' => 600,
            'ssh_job_max_script_kib', 'ssh_command_stdout_kib', 'ssh_job_output_window_kib',
            'ssh_file_read_window_kib', 'ssh_file_write_window_kib', 'ssh_file_list_name_kib' => 16,
            'ssh_command_stderr_kib' => 8,
            'wp_ability_input_kib', 'dcr_registration_capacity' => 1024,
            'batch_max_parallelism' => max(1, (int) config('batch.max_parallelism', 4)),
            'batch_global_active' => max(1, (int) config('batch.global_active', 4)),
            'batch_user_active' => max(1, (int) config('batch.user_active', 2)),
            'batch_worker_max_children' => max(1, (int) config('batch.worker_max_children', 16)),
            'batch_worker_max_seconds' => max(1, (int) config('batch.worker_max_seconds', 50)),
            default => throw new RuntimeException('Operational setting has no default: '.$key),
        };
    }

    public function wpAbilityInputBytes(): int
    {
        return ($this->overrides()['wp_ability_input_kib'] ?? (int) $this->defaultValue('wp_ability_input_kib')) * 1024;
    }

    public function dcrRegistrationCapacity(): int
    {
        return $this->overrides()['dcr_registration_capacity'] ?? (int) $this->defaultValue('dcr_registration_capacity');
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
        return (int) ($this->defaultValue($key) * 1024);
    }

    /** @return array{connect:int,request:int} */
    public function httpTimeoutsSeconds(): array
    {
        $overrides = $this->overrides();

        // Existing env/config installations retain their exact normalized
        // fallback, including before the first operational-settings migration.
        $connect = $overrides['wp_connect_timeout_seconds']
            ?? (int) $this->defaultValue('wp_connect_timeout_seconds');
        $request = $overrides['wp_request_timeout_seconds']
            ?? (int) $this->defaultValue('wp_request_timeout_seconds');

        return ['connect' => $connect, 'request' => max($connect, $request)];
    }

    /** Source/.env-owned WordPress file-param budget, separate from SSH. */
    /** @return array{max_bytes:int,max_seconds:int} */
    public function chatgptWordpressFileLimits(): array
    {
        return [
            'max_bytes' => min(67108864, max(1, (int) config('bridge.file_input.max_bytes', 8388608))),
            'max_seconds' => min(120, max(1, (int) config('bridge.file_input.max_seconds', 120))),
        ];
    }

    /** @return array{max_bytes:int,max_seconds:int} */
    public function sshTransferLimits(): array
    {
        $overrides = $this->overrides();
        $configuredMax = (int) ($this->defaultValue('ssh_transfer_max_kib') * 1024);
        $configuredSeconds = (int) $this->defaultValue('ssh_transfer_max_seconds');

        return [
            'max_bytes' => isset($overrides['ssh_transfer_max_kib'])
                ? $overrides['ssh_transfer_max_kib'] * 1024 : $configuredMax,
            'max_seconds' => $overrides['ssh_transfer_max_seconds'] ?? $configuredSeconds,
        ];
    }

    /** @return array{max_bytes:int,max_seconds:int} */
    public function sshCommandLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'max_bytes' => ($overrides['ssh_command_max_kib'] ?? (int) $this->defaultValue('ssh_command_max_kib')) * 1024,
            'max_seconds' => $overrides['ssh_command_timeout_seconds'] ?? (int) $this->defaultValue('ssh_command_timeout_seconds'),
        ];
    }

    /** @return array{stdout_bytes:int,stderr_bytes:int} */
    public function sshCommandOutputLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'stdout_bytes' => ($overrides['ssh_command_stdout_kib'] ?? (int) $this->defaultValue('ssh_command_stdout_kib')) * 1024,
            'stderr_bytes' => ($overrides['ssh_command_stderr_kib'] ?? (int) $this->defaultValue('ssh_command_stderr_kib')) * 1024,
        ];
    }

    public function sshJobOutputWindowBytes(): int
    {
        return ($this->overrides()['ssh_job_output_window_kib'] ?? (int) $this->defaultValue('ssh_job_output_window_kib')) * 1024;
    }

    /** @return array{read_bytes:int,write_bytes:int,list_name_bytes:int} */
    public function sshFileLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'read_bytes' => ($overrides['ssh_file_read_window_kib'] ?? (int) $this->defaultValue('ssh_file_read_window_kib')) * 1024,
            'write_bytes' => ($overrides['ssh_file_write_window_kib'] ?? (int) $this->defaultValue('ssh_file_write_window_kib')) * 1024,
            'list_name_bytes' => ($overrides['ssh_file_list_name_kib'] ?? (int) $this->defaultValue('ssh_file_list_name_kib')) * 1024,
        ];
    }

    /** @return array{max_active_per_user:int,max_runtime_seconds:int,retention_hours:int,preparing_grace_seconds:int,reconcile_grace_seconds:int,max_script_bytes:int} */
    public function sshJobLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'max_active_per_user' => $overrides['ssh_job_max_active_per_user'] ?? (int) $this->defaultValue('ssh_job_max_active_per_user'),
            'max_runtime_seconds' => $overrides['ssh_job_max_runtime_seconds'] ?? (int) $this->defaultValue('ssh_job_max_runtime_seconds'),
            'retention_hours' => $overrides['ssh_job_retention_hours'] ?? (int) $this->defaultValue('ssh_job_retention_hours'),
            'preparing_grace_seconds' => $overrides['ssh_job_preparing_grace_seconds'] ?? (int) $this->defaultValue('ssh_job_preparing_grace_seconds'),
            'reconcile_grace_seconds' => $overrides['ssh_job_reconcile_grace_seconds'] ?? (int) $this->defaultValue('ssh_job_reconcile_grace_seconds'),
            'max_script_bytes' => ($overrides['ssh_job_max_script_kib'] ?? (int) $this->defaultValue('ssh_job_max_script_kib')) * 1024,
        ];
    }

    /** @return array{max_parallelism:int,global_active:int,user_active:int,worker_max_children:int,worker_max_seconds:int} */
    public function batchLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'max_parallelism' => $overrides['batch_max_parallelism'] ?? (int) $this->defaultValue('batch_max_parallelism'),
            'global_active' => $overrides['batch_global_active'] ?? (int) $this->defaultValue('batch_global_active'),
            'user_active' => $overrides['batch_user_active'] ?? (int) $this->defaultValue('batch_user_active'),
            'worker_max_children' => $overrides['batch_worker_max_children'] ?? (int) $this->defaultValue('batch_worker_max_children'),
            'worker_max_seconds' => $overrides['batch_worker_max_seconds'] ?? (int) $this->defaultValue('batch_worker_max_seconds'),
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
     * Apply a version-checked setting delta; null resets an override.
     *
     * @param  array<string, int|null>  $values
     */
    public function save(User $actor, array $values, int $expectedVersion): void
    {
        $keys = array_keys($values);
        if (! self::acceptsFormKeys($keys)) {
            throw ValidationException::withMessages([
                'values' => 'The operational settings request has an unknown or missing field.',
            ]);
        }
        $next = DB::transaction(function () use ($actor, $expectedVersion, $values): array {
            $record = DB::table('operational_settings')->where('id', 1)
                ->lockForUpdate()->first();
            if ($record === null || (int) $record->version !== $expectedVersion) {
                throw ValidationException::withMessages([
                    'version' => 'Operational settings changed. Reload the page before saving.',
                ]);
            }
            foreach (self::columnKeys() as $key) {
                if (! property_exists($record, $key)) {
                    throw new RuntimeException('Operational settings schema is missing required column: '.$key);
                }
            }

            $old = $this->combineOverrides($record);
            $next = [];
            foreach (self::SETTING_RANGES as $key => $range) {
                $value = array_key_exists($key, $values) ? $values[$key] : ($old[$key] ?? null);
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
                ?? (int) $this->defaultValue('wp_connect_timeout_seconds');
            $request = $next['wp_request_timeout_seconds']
                ?? (int) $this->defaultValue('wp_request_timeout_seconds');
            // Explicit deadline overrides must form a valid effective pair.
            // With no override, the HTTP runtime normalizes the config defaults.
            $hasNetworkOverride = isset($next['wp_connect_timeout_seconds'])
                || isset($next['wp_request_timeout_seconds']);
            if ($hasNetworkOverride && $connect > $request) {
                throw ValidationException::withMessages([
                    'values.wp_request_timeout_seconds' => 'The overall request timeout must be at least the connection timeout.',
                ]);
            }

            if ($old === $next) {
                return $next;
            }
            $revision = (int) $record->version + 1;
            $now = now();
            $columns = [];
            foreach (self::columnKeys() as $key) {
                $columns[$key] = $next[$key] ?? null;
            }
            DB::table('operational_settings')->where('id', 1)->update([
                'overrides' => json_encode(array_intersect_key($next, array_flip(self::JSON_KEYS)), JSON_THROW_ON_ERROR),
                ...$columns,
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

            return $next;
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
        foreach (self::columnKeys() as $key) {
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
            if (! is_string($key) || ! in_array($key, self::JSON_KEYS, true)
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
