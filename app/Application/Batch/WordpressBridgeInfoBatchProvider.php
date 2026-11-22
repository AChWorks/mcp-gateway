<?php

namespace App\Application\Batch;

use App\Application\Operations\OperationalSettings;
use App\Application\Targets\WordpressTargetOperations;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Closure;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** Only this fixed read-only Bridge capability enters Batch; no publishing. */
final readonly class WordpressBridgeInfoBatchProvider implements TargetBatchOperationProvider
{
    public function __construct(
        private WordpressTargetOperations $wordpress,
        private OperationalSettings $settings,
    ) {}

    public function key(): string
    {
        return 'wordpress.bridge.info';
    }

    public function connectorType(): string
    {
        return 'wp_ai_bridge';
    }

    public function permission(): GatewayPermission
    {
        return GatewayPermission::WordpressAbilitiesExecuteReadonly;
    }

    public function isEffectful(): bool
    {
        return false;
    }

    public function validArguments(array $arguments): bool
    {
        return $arguments === [];
    }

    public function remoteTimeoutSeconds(array $arguments): int
    {
        return max(30, $this->settings->httpTimeoutsSeconds()['request']);
    }

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess): array
    {
        $result = $this->wordpress->execute(
            $user, $target->target_id, 'wp-ai-bridge/bridge-info', [],
            readonlyOnly: true, requiresAiAccess: $requiresAiAccess, beforeRemoteEffect: $beforeRemoteEffect,
        );
        if (! ($result['ok'] ?? false)) {
            $error = is_array($result['error'] ?? null) ? $result['error'] : [];
            $code = (string) ($error['code'] ?? 'wordpress_read_failed');
            $diagnostics = [
                'failure_origin' => 'downstream_mcp',
                'failure_stage' => 'operation',
                'source_error_code' => $code,
            ];
            if (is_string($error['diagnostic_reference'] ?? null)) {
                $diagnostics['downstream_diagnostic_reference'] = $error['diagnostic_reference'];
            }
            if (is_string($error['message'] ?? null)) {
                $diagnostics['source_error_message'] = $error['message'];
            }
            if (is_string($error['next_step'] ?? null)) {
                $diagnostics['source_error_details'] = ['provider_next_step' => $error['next_step']];
            }

            // Native WordPress already stored its redacted source failure under
            // a separate diagnostic reference. Restore that precise cause into
            // the initiating Batch actor's scoped Activity record: CLI's native
            // system-actor row is otherwise unreadable by non-Owner MCP users.
            // Require the same Target record; never copy raw Tool payloads.
            $reference = $diagnostics['downstream_diagnostic_reference'] ?? null;
            if (is_string($reference) && Str::isUuid($reference)) {
                $native = DB::table('activity_events')
                    ->where('correlation_id', $reference)
                    ->where('target_record_id', $target->getKey())
                    ->where('outcome', '!=', 'success')
                    ->orderByDesc('id')->first(['error_code', 'diagnostic_context']);
                if ($native !== null) {
                    $context = json_decode((string) $native->diagnostic_context, true);
                    if (is_array($context)) {
                        $details = OperationDiagnostics::safeContext($context);
                        $diagnostics = [...$diagnostics, ...$details,
                            'downstream_diagnostic_reference' => $reference];
                    }
                    if (is_string($native->error_code) && $native->error_code !== '') {
                        $diagnostics['provider_error_code'] = $native->error_code;
                    }
                }
            }

            return [
                'ok' => false, 'status' => $code === 'outcome_unknown' ? 'outcome_unknown' : 'failed',
                'error_code' => $code, 'diagnostics' => $diagnostics,
            ];
        }

        return ['ok' => true, 'status' => 'completed', 'result' => $result['result'] ?? []];
    }
}
