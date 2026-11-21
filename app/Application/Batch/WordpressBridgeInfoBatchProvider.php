<?php

namespace App\Application\Batch;

use App\Application\Targets\WordpressTargetOperations;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use Closure;

/** Only this fixed read-only Bridge capability enters Batch; no publishing. */
final readonly class WordpressBridgeInfoBatchProvider implements TargetBatchOperationProvider
{
    public function __construct(private WordpressTargetOperations $wordpress) {}

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

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess): array
    {
        $result = $this->wordpress->execute(
            $user, $target->target_id, 'wp-ai-bridge/bridge-info', [],
            readonlyOnly: true, requiresAiAccess: $requiresAiAccess, beforeRemoteEffect: $beforeRemoteEffect,
        );
        if (! ($result['ok'] ?? false)) {
            return ['ok' => false, 'status' => (($result['error']['code'] ?? '') === 'outcome_unknown')
                ? 'outcome_unknown' : 'failed',
                'error_code' => (string) ($result['error']['code'] ?? 'wordpress_read_failed')];
        }

        return ['ok' => true, 'status' => 'completed', 'result' => $result['result'] ?? []];
    }
}
