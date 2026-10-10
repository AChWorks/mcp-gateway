<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpException;
use App\Models\User;
use App\Support\CorrelationId;
use JsonException;

final readonly class WordpressTargetMcpToolHandlers
{
    public function __construct(
        private AccessControl $access,
        private ActivityRecorder $activity,
        private WpAiBridgeMcpClient $bridge,
    ) {}

    /** @return array<string, mixed> */
    public function read(
        User $user,
        string $target_id,
        ?string $ability = null,
        int $page = 1,
        int $per_page = 10,
        ?string $namespace = null,
        ?string $search = null,
    ): array {
        $operation = 'wordpress-abilities-read';
        $target = $this->target($user, $target_id, GatewayPermission::WordpressAbilitiesInspect);
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found', 'WordPress Target is unavailable.');
        }

        $ability = $this->optional($ability);
        $namespace = $this->optional($namespace);
        $search = $this->optional($search);
        if ($page < 1 || $page > 100000 || $per_page < 1 || $per_page > 100
            || $this->invalidFilter($ability) || $this->invalidFilter($namespace) || $this->invalidFilter($search)
            || ($ability !== null && ($page !== 1 || $per_page !== 10 || $namespace !== null || $search !== null))) {
            return $this->failed($operation, $target, 'invalid_input', 'Invalid WordPress catalog arguments.');
        }

        try {
            $catalog = $this->bridge->readAbilities($target, CorrelationId::current(), $ability, $page, $per_page, $namespace, $search);
        } catch (WpAiBridgeTargetConnectionException|WpAiBridgeMcpException $exception) {
            return $this->failed($operation, $target, $exception->reason, 'WordPress catalog request could not complete safely.');
        }

        $this->activity->record(CorrelationId::current(), $operation, 'success', $target);

        return ['ok' => true, 'target_id' => $target->target_id, 'catalog' => $catalog];
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array<string, mixed>
     */
    public function execute(User $user, string $target_id, string $ability, array $input): array
    {
        $operation = 'wordpress-ability-execute';
        $target = $this->target($user, $target_id);
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found', 'WordPress Target is unavailable.');
        }

        $ability = trim($ability);
        if ($ability === '' || mb_strlen($ability) > 255 || preg_match('/[\x00-\x1F\x7F]/', $ability) === 1) {
            return $this->failed($operation, $target, 'invalid_input', 'Invalid WordPress Ability name.');
        }
        try {
            if (strlen(json_encode($input, JSON_THROW_ON_ERROR)) > 262144) {
                return $this->failed($operation, $target, 'invalid_input', 'Ability input exceeds the bounded request limit.');
            }
        } catch (JsonException) {
            return $this->failed($operation, $target, 'invalid_input', 'Ability input must be valid JSON.');
        }

        // A single Target-scoped authorization snapshot bounds DB work and
        // freezes the decisions for this one logical request (not a cache).
        $allowed = $this->access->allowsTargetPermissions($user, $target, [
            GatewayPermission::WordpressAbilitiesExecuteReadonly,
            GatewayPermission::WordpressAbilitiesExecuteMutating,
            GatewayPermission::WordpressAbilitiesExecuteDestructive,
            GatewayPermission::WordpressAbilitiesExecuteUnclassified,
        ]);
        if (! in_array(true, $allowed, true)) {
            return $this->failed($operation, $target, 'forbidden', 'WordPress execution is not authorized.');
        }

        try {
            $result = $this->bridge->executeAuthorizedAbility(
                $target,
                $ability,
                $input,
                CorrelationId::current(),
                static fn (\App\Domain\Access\AbilityExecutionClass $class): bool => $allowed[$class->permission()->value] ?? false,
            );
        } catch (WpAiBridgeTargetConnectionException|WpAiBridgeMcpException $exception) {
            return $this->failed($operation, $target, $exception->reason, 'WordPress Ability could not complete safely.');
        }

        $this->activity->record(CorrelationId::current(), $operation, 'success', $target);

        return ['ok' => true, 'target_id' => $target->target_id, 'ability' => $ability, 'result' => $result];
    }

    private function target(User $user, string $targetId, ?GatewayPermission $permission = null): ?Target
    {
        $targetId = trim($targetId);
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            return null;
        }

        $query = $permission instanceof GatewayPermission
            ? $this->access->scopeTargets(Target::query(), $user, $permission)
            : $this->access->scopePrincipalTargets(Target::query(), $user);

        return $query->where('target_id', $targetId)->where('connector_type', 'wp_ai_bridge')->first();
    }

    private function optional(?string $value): ?string
    {
        $value = $value === null ? null : trim($value);

        return $value === '' ? null : $value;
    }

    private function invalidFilter(?string $value): bool
    {
        return $value !== null
            && (mb_strlen($value) > 255 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1);
    }

    /** @return array<string, mixed> */
    private function failed(string $operation, ?Target $target, string $code, string $message): array
    {
        $this->activity->record(
            CorrelationId::current(),
            $operation,
            $code === 'outcome_unknown' ? 'unknown' : 'failure',
            $target,
            $code,
        );

        return ['ok' => false, 'error' => ['code' => $code, 'message' => $message]];
    }
}
