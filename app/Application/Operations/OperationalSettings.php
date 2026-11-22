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
        // Add new controls *after* existing ones: legacy saved browser tabs
        // submit prefix allowlists, retaining every absent newer setting.
        'ssh_command_stdout_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_command_stderr_kib' => ['minimum' => 8, 'maximum' => 512],
        'ssh_job_output_window_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_file_read_window_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_file_write_window_kib' => ['minimum' => 16, 'maximum' => 512],
        'ssh_file_list_name_kib' => ['minimum' => 16, 'maximum' => 512],
        // Appended to keep legacy open-form prefixes stable. The Bridge whole
        // JSON-RPC request limit and the DCR admission-rate quota are separate.
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

    /** @var array<string, int>|null */
    private ?array $cachedOverrides = null;

    /** @return array<string, array{minimum:int,maximum:int}> */
    public static function allowed(): array
    {
        return self::SETTING_RANGES;
    }

    /**
     * Released form schemas are ordered prefixes. Preserve older browser tabs
     * without admitting arbitrary missing fields or clearing new overrides.
     *
     * @param  list<string>  $names
     */
    public static function acceptsFormKeys(array $names): bool
    {
        $all = array_keys(self::SETTING_RANGES);
        sort($names);
        foreach ([2, 4, 6, 8, 13, 14, 20, 22, count($all)] as $size) {
            $prefix = array_slice($all, 0, $size);
            sort($prefix);
            if ($names === $prefix) {
                return true;
            }
        }

        return false;
    }

    public function wpAbilityInputBytes(): int
    {
        return ($this->overrides()['wp_ability_input_kib'] ?? 1024) * 1024;
    }

    public function dcrRegistrationCapacity(): int
    {
        return $this->overrides()['dcr_registration_capacity'] ?? 1024;
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
        $configuredMax = min(67108864, max(1, (int) config('ssh.file_transfer.max_bytes', 8388608)));
        $configuredSeconds = min(3600, max(1, (int) config('ssh.file_transfer.max_seconds', 30)));

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
            'max_bytes' => ($overrides['ssh_command_max_kib'] ?? 8) * 1024,
            'max_seconds' => $overrides['ssh_command_timeout_seconds'] ?? 15,
        ];
    }

    /** @return array{stdout_bytes:int,stderr_bytes:int} */
    public function sshCommandOutputLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'stdout_bytes' => ($overrides['ssh_command_stdout_kib'] ?? 16) * 1024,
            'stderr_bytes' => ($overrides['ssh_command_stderr_kib'] ?? 8) * 1024,
        ];
    }

    public function sshJobOutputWindowBytes(): int
    {
        return ($this->overrides()['ssh_job_output_window_kib'] ?? 16) * 1024;
    }

    /** @return array{read_bytes:int,write_bytes:int,list_name_bytes:int} */
    public function sshFileLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'read_bytes' => ($overrides['ssh_file_read_window_kib'] ?? 16) * 1024,
            'write_bytes' => ($overrides['ssh_file_write_window_kib'] ?? 16) * 1024,
            'list_name_bytes' => ($overrides['ssh_file_list_name_kib'] ?? 16) * 1024,
        ];
    }

    /** @return array{max_active_per_user:int,max_runtime_seconds:int,retention_hours:int,preparing_grace_seconds:int,reconcile_grace_seconds:int,max_script_bytes:int} */
    public function sshJobLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'max_active_per_user' => $overrides['ssh_job_max_active_per_user'] ?? 2,
            'max_runtime_seconds' => $overrides['ssh_job_max_runtime_seconds'] ?? 300,
            'retention_hours' => $overrides['ssh_job_retention_hours'] ?? 24,
            'preparing_grace_seconds' => $overrides['ssh_job_preparing_grace_seconds'] ?? 120,
            'reconcile_grace_seconds' => $overrides['ssh_job_reconcile_grace_seconds'] ?? 600,
            'max_script_bytes' => ($overrides['ssh_job_max_script_kib'] ?? 16) * 1024,
        ];
    }

    /** @return array{max_parallelism:int,global_active:int,user_active:int,worker_max_children:int,worker_max_seconds:int} */
    public function batchLimits(): array
    {
        $overrides = $this->overrides();

        return [
            'max_parallelism' => $overrides['batch_max_parallelism'] ?? max(1, (int) config('batch.max_parallelism', 4)),
            'global_active' => $overrides['batch_global_active'] ?? max(1, (int) config('batch.global_active', 4)),
            'user_active' => $overrides['batch_user_active'] ?? max(1, (int) config('batch.user_active', 2)),
            'worker_max_children' => $overrides['batch_worker_max_children'] ?? max(1, (int) config('batch.worker_max_children', 16)),
            'worker_max_seconds' => $overrides['batch_worker_max_seconds'] ?? max(1, (int) config('batch.worker_max_seconds', 50)),
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
        if (! self::acceptsFormKeys($keys)) {
            throw ValidationException::withMessages([
                'values' => 'The operational settings request has an unknown or missing field.',
            ]);
        }
        $all = array_keys(self::SETTING_RANGES);
        if (count($keys) !== count($all)) {
            $previous = $this->state()['overrides'];
            foreach ($all as $key) {
                if (! array_key_exists($key, $values)) {
                    $values[$key] = $previous[$key] ?? null;
                }
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
                || ! property_exists($record, 'wp_request_timeout_seconds')
                || ! property_exists($record, 'ssh_command_timeout_seconds')
                || ! property_exists($record, 'ssh_command_max_kib')
                || ! property_exists($record, 'ssh_job_max_active_per_user')
                || ! property_exists($record, 'ssh_job_reconcile_grace_seconds')
                || ! property_exists($record, 'ssh_job_max_script_kib')
                || ! property_exists($record, 'ssh_command_stdout_kib')
                || ! property_exists($record, 'ssh_file_list_name_kib')
                || ! property_exists($record, 'wp_ability_input_kib')
                || ! property_exists($record, 'dcr_registration_capacity')
                || ! property_exists($record, 'batch_max_parallelism')
                || ! property_exists($record, 'batch_global_active')
                || ! property_exists($record, 'batch_user_active')
                || ! property_exists($record, 'batch_worker_max_children')
                || ! property_exists($record, 'batch_worker_max_seconds')) {
                throw new RuntimeException('Operational settings schema is missing required columns.');
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
                'ssh_command_timeout_seconds' => $next['ssh_command_timeout_seconds'] ?? null,
                'ssh_command_max_kib' => $next['ssh_command_max_kib'] ?? null,
                'ssh_job_max_active_per_user' => $next['ssh_job_max_active_per_user'] ?? null,
                'ssh_job_max_runtime_seconds' => $next['ssh_job_max_runtime_seconds'] ?? null,
                'ssh_job_retention_hours' => $next['ssh_job_retention_hours'] ?? null,
                'ssh_job_preparing_grace_seconds' => $next['ssh_job_preparing_grace_seconds'] ?? null,
                'ssh_job_reconcile_grace_seconds' => $next['ssh_job_reconcile_grace_seconds'] ?? null,
                'ssh_job_max_script_kib' => $next['ssh_job_max_script_kib'] ?? null,
                'ssh_command_stdout_kib' => $next['ssh_command_stdout_kib'] ?? null,
                'ssh_command_stderr_kib' => $next['ssh_command_stderr_kib'] ?? null,
                'ssh_job_output_window_kib' => $next['ssh_job_output_window_kib'] ?? null,
                'ssh_file_read_window_kib' => $next['ssh_file_read_window_kib'] ?? null,
                'ssh_file_write_window_kib' => $next['ssh_file_write_window_kib'] ?? null,
                'ssh_file_list_name_kib' => $next['ssh_file_list_name_kib'] ?? null,
                'wp_ability_input_kib' => $next['wp_ability_input_kib'] ?? null,
                'dcr_registration_capacity' => $next['dcr_registration_capacity'] ?? null,
                'batch_max_parallelism' => $next['batch_max_parallelism'] ?? null,
                'batch_global_active' => $next['batch_global_active'] ?? null,
                'batch_user_active' => $next['batch_user_active'] ?? null,
                'batch_worker_max_children' => $next['batch_worker_max_children'] ?? null,
                'batch_worker_max_seconds' => $next['batch_worker_max_seconds'] ?? null,
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
            'ssh_transfer_max_kib', 'ssh_transfer_max_seconds',
            'ssh_command_timeout_seconds', 'ssh_command_max_kib',
            'ssh_job_max_active_per_user', 'ssh_job_max_runtime_seconds',
            'ssh_job_retention_hours', 'ssh_job_preparing_grace_seconds',
            'ssh_job_reconcile_grace_seconds', 'ssh_job_max_script_kib',
            'ssh_command_stdout_kib', 'ssh_command_stderr_kib',
            'ssh_job_output_window_kib', 'ssh_file_read_window_kib',
            'ssh_file_write_window_kib', 'ssh_file_list_name_kib',
            'wp_ability_input_kib', 'dcr_registration_capacity',
            'batch_max_parallelism', 'batch_global_active', 'batch_user_active',
            'batch_worker_max_children', 'batch_worker_max_seconds'] as $key) {
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
