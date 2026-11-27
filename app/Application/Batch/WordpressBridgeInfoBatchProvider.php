<?php

namespace App\Application\Batch;

use App\Application\Operations\OperationalSettings;
use App\Application\Targets\WordpressOperationEvidence;
use App\Application\Targets\WordpressTargetOperations;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityAttribution;
use App\Models\User;
use Closure;

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
        // This native read is a sequence of FOUR independently timed HTTP
        // requests: initialize, ability classification, execute, close. A
        // stale access bearer may first need one refresh request; its single-
        // use ambiguous-response recovery can take another 45 seconds before
        // a definitive result. Leasing for just ONE HTTP request would let a
        // second worker declare a legitimate slow read outcome_unknown while
        // its first worker was still running. The shared Worker adds the
        // separately configured crash/DB margin to this provider budget.
        $requestSeconds = $this->settings->httpTimeoutsSeconds()['request'];

        return 5 * $requestSeconds + 45;
    }

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess, Closure $admitRemoteEffect, ActivityAttribution $attribution): array
    {
        $evidence = new WordpressOperationEvidence($attribution);
        $result = $this->wordpress->execute(
            $user, $target->target_id, 'wp-ai-bridge/bridge-info', [],
            readonlyOnly: true, requiresAiAccess: $requiresAiAccess, beforeRemoteEffect: $beforeRemoteEffect,
            admitRemoteEffect: $admitRemoteEffect, evidence: $evidence,
        );
        if (! ($result['ok'] ?? false)) {
            $error = is_array($result['error'] ?? null) ? $result['error'] : [];
            $code = (string) ($error['code'] ?? 'wordpress_read_failed');
            $diagnostics = [
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

            // Native result evidence is captured before best-effort Activity.
            // Neither retention nor a failed Activity insert changes truth.
            $diagnostics = [...$diagnostics, ...$evidence->diagnostics];

            return [
                'ok' => false, 'status' => $code === 'outcome_unknown' || ($diagnostics['effect_unconfirmed'] ?? false) === true ? 'outcome_unknown' : 'failed',
                'error_code' => $code, 'diagnostics' => $diagnostics,
            ];
        }

        return ['ok' => true, 'status' => 'completed', 'result' => $result['result'] ?? []];
    }
}
