<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Domain\Access\AbilityExecutionClass;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpException;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use App\Support\OperationTiming;
use JsonException;

final readonly class WordpressTargetOperations
{
    public function __construct(
        private AccessControl $access,
        private ActivityRecorder $activity,
        private WpAiBridgeMcpClient $bridge,
        private ClientProfileRegistry $profiles,
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
        $timing = OperationTiming::forWordpress();
        $lookedUpAt = $timing?->stamp() ?? 0;
        $target = $this->target($user, $target_id, GatewayPermission::WordpressAbilitiesInspect);
        $timing?->finish('target_lookup_ms', $lookedUpAt);
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found', 'WordPress Target is unavailable.');
        }

        if (TargetOperationGate::isPaused($target)) {
            return $this->failed($operation, $target, 'target_paused', 'This Target is paused by the Gateway Owner.');
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
            $catalog = $this->bridge->readAbilities($target, CorrelationId::current(), $ability, $page, $per_page, $namespace, $search, $timing);
        } catch (WpAiBridgeTargetConnectionException|WpAiBridgeMcpException $exception) {
            return $this->failed($operation, $target, $exception->reason, 'WordPress catalog request could not complete safely.', [
                ...$this->safeDetails($exception), ...($timing?->details(true) ?? []),
            ]);
        }

        $this->activity->record(CorrelationId::current(), $operation, 'success', $target, null, $timing?->details() ?? []);

        return ['ok' => true, 'target_id' => $target->target_id, 'catalog' => $catalog];
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array<string, mixed>
     */
    public function execute(User $user, string $target_id, string $ability, array $input, bool $readonlyOnly = false, bool $requiresAiAccess = false): array
    {
        $operation = 'wordpress-ability-execute';
        $timing = OperationTiming::forWordpress();
        $lookedUpAt = $timing?->stamp() ?? 0;
        $target = $this->target($user, $target_id);
        if ($requiresAiAccess && ! $user->ai_access_enabled) {
            return $this->failed($operation, null, 'forbidden', 'AI connection is not authorized.');
        }
        $timing?->finish('target_lookup_ms', $lookedUpAt);
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

        // A single Target-scoped request-entry snapshot bounds initial
        // authority. Its decisions form a ceiling, not a permanent grant:
        // the classified permission is refreshed immediately before dispatch.
        $authorizedAt = $timing?->stamp() ?? 0;
        try {
            // A human read-only pilot can only narrow the existing MCP
            // authority. Classification is trusted downstream metadata
            // checked again immediately before the actual tool dispatch.
            $permissions = $readonlyOnly
                ? [GatewayPermission::WordpressAbilitiesExecuteReadonly]
                : [
                    GatewayPermission::WordpressAbilitiesExecuteReadonly,
                    GatewayPermission::WordpressAbilitiesExecuteMutating,
                    GatewayPermission::WordpressAbilitiesExecuteDestructive,
                    GatewayPermission::WordpressAbilitiesExecuteUnclassified,
                ];
            $allowed = $this->access->allowsTargetPermissions($user, $target, $permissions);
        } finally {
            $timing?->finish('authorization_ms', $authorizedAt);
        }
        if (! in_array(true, $allowed, true)) {
            return $this->failed($operation, $target, 'forbidden', 'WordPress execution is not authorized.');
        }
        if (TargetOperationGate::isPaused($target)) {
            return $this->failed($operation, $target, 'target_paused', 'This Target is paused by the Gateway Owner.');
        }

        try {
            $result = $this->bridge->executeAuthorizedAbility(
                $target,
                $ability,
                $input,
                CorrelationId::current(),
                function (AbilityExecutionClass $class) use ($allowed, $user, $target, $readonlyOnly, $requiresAiAccess): bool {
                    $permission = $class->permission();
                    // The request-entry snapshot is an immutable ceiling:
                    // later grants cannot elevate a previously denied class.
                    if (! ($allowed[$permission->value] ?? false)) {
                        return false;
                    }

                    // Downstream classification takes network time. Refresh the
                    // actor and the exact Target-scoped permission immediately
                    // before the connector dispatches; never trust an in-memory
                    // User role/enabled state or stale group membership.
                    $currentUser = User::query()->find($user->getKey());

                    if (! $currentUser instanceof User || ($requiresAiAccess && ! $currentUser->ai_access_enabled)) {
                        return false;
                    }

                    // The Admin pilot also requires Target visibility. Check
                    // both rights in one fresh evaluation so a revoked view
                    // grant cannot survive classification and dispatch.
                    $permissions = $readonlyOnly
                        ? [$permission, GatewayPermission::TargetsView]
                        : [$permission];
                    $current = $this->access->allowsTargetPermissions($currentUser, $target, $permissions);

                    return ($current[$permission->value] ?? false)
                        && (! $readonlyOnly || ($current[GatewayPermission::TargetsView->value] ?? false));
                },
                $timing,
            );
        } catch (WpAiBridgeTargetConnectionException|WpAiBridgeMcpException $exception) {
            return $this->failed($operation, $target, $exception->reason, 'WordPress Ability could not complete safely.', [
                ...$this->safeDetails($exception), ...($timing?->details(true) ?? []),
            ]);
        }

        $this->activity->record(CorrelationId::current(), $operation, 'success', $target, null, $timing?->details() ?? []);

        return ['ok' => true, 'target_id' => $target->target_id, 'ability' => $ability, 'result' => $result];
    }

    /**
     * A deliberately restricted, create-only LIVE post operation.
     * The wire Ability name and ALL mutation-sensitive fields are fixed by
     * Gateway, never selected by the caller or by mutable catalog metadata.
     * Caller identity/profile values must come from authenticated MCP context.
     *
     * @return array<string,mixed>
     */
    public function publishCreate(
        User $user,
        string $targetId,
        string $title,
        string $content,
        string $operationId,
        ?string $clientId = null,
        ?string $profileKey = null,
        ?int $profileGeneration = null,
    ): array {
        $operation = 'wordpress-content-publish-create';
        $target = $this->target($user, $targetId, GatewayPermission::WordpressContentPublishCreate);
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found', 'WordPress Target is unavailable.');
        }

        $throughAi = $clientId !== null || $profileKey !== null || $profileGeneration !== null;
        if ($title === '' || mb_strlen($title) > 200 || strlen($content) > 65536
            || trim($content) === ''
            || preg_match('/^[A-Za-z0-9_.:-]{8,128}$/D', $operationId) !== 1
            || ($throughAi && ($clientId === null || $clientId === ''
                || $profileKey === null || $profileKey === ''
                || $profileGeneration === null || $profileGeneration < 1))) {
            return $this->failed($operation, $target, 'invalid_input', 'Invalid bounded WordPress post input or operation identity.');
        }

        // The initial positive grant is an immutable admission ceiling.
        // An account, profile, membership or denial change during remote
        // catalog classification is independently rechecked at dispatch.
        $admitted = $this->access->allowsWordpressPublish($user, $target)
            && (! $throughAi || ($user->ai_access_enabled
                && $this->profiles->authorizes((string) $clientId, $profileKey, $profileGeneration)));
        if (! $admitted) {
            return $this->failed($operation, $target, 'forbidden', 'WordPress publication is not authorized.');
        }
        if (TargetOperationGate::isPaused($target)) {
            return $this->failed($operation, $target, 'target_paused', 'This Target is paused by the Gateway Owner.');
        }

        $input = [
            'action' => 'create',
            'post_type' => 'post',
            'status' => 'publish',
            'title' => $title,
            'content' => $content,
            // Bridge's own claim identity knows the WordPress principal and
            // OAuth client, but not the initiating Gateway User. Namespace
            // the caller's stable key so 100+ scoped users cannot collide.
            'operation_id' => 'gw-'.hash('sha256', "wp-post-create\0".$user->getKey()."\0".$operationId),
        ];
        $timing = OperationTiming::forWordpress();
        try {
            $result = $this->bridge->executeAuthorizedAbility(
                $target,
                'wp-ai-bridge/content-upsert',
                $input,
                CorrelationId::current(),
                function (AbilityExecutionClass $class) use ($user, $target, $clientId, $profileKey, $profileGeneration, $throughAi): bool {
                    if ($class !== AbilityExecutionClass::Mutating) {
                        return false;
                    }

                    $current = User::query()->find($user->getKey());

                    return $current instanceof User
                        && $this->access->allowsWordpressPublish($current, $target)
                        && (! $throughAi || ($current->ai_access_enabled
                            && $this->profiles->authorizes((string) $clientId, $profileKey, $profileGeneration)));
                },
                $timing,
                fn (?array $contract, AbilityExecutionClass $class): bool => $this->supportsPublishCreate($contract, $class),
            );
        } catch (WpAiBridgeTargetConnectionException|WpAiBridgeMcpException $exception) {
            return $this->failed($operation, $target, $exception->reason, 'WordPress publication could not complete safely.', [
                ...$this->safeDetails($exception), ...($timing?->details(true) ?? []),
            ]);
        }

        // After an effectful dispatch, malformed or conflicting provider
        // readback is UNKNOWN, never a safe failure or automatic retry.
        if (! is_array($result) || ! is_int($result['id'] ?? null) || $result['id'] < 1
            || ($result['status'] ?? null) !== 'publish' || ($result['post_type'] ?? null) !== 'post') {
            return $this->failed($operation, $target, 'outcome_unknown', 'Publication may have completed, but its remote identity or live state is unverified.', [
                'effect_unconfirmed' => true, 'retry_safe' => false,
            ]);
        }

        $this->activity->record(CorrelationId::current(), $operation, 'success', $target, null, $timing?->details() ?? []);

        // Content stays on its originating WordPress Target. Do not echo
        // arbitrary untrusted provider result fields or raw post content.
        return [
            'ok' => true,
            'target_id' => $target->target_id,
            'remote_id' => $result['id'],
            'status' => 'publish',
            'post_type' => 'post',
        ];
    }

    /** @param array<string,mixed>|null $contract */
    private function supportsPublishCreate(?array $contract, AbilityExecutionClass $class): bool
    {
        if ($class !== AbilityExecutionClass::Mutating || ! is_array($contract)
            || ($contract['name'] ?? null) !== 'wp-ai-bridge/content-upsert'
            || ($contract['bridge_delegation'] ?? null) !== 'ability_specific'
            || ($contract['mcp_type'] ?? null) !== 'tool') {
            return false;
        }

        $schema = $contract['input_schema'] ?? null;
        if (! is_array($schema) || ($schema['type'] ?? null) !== 'object'
            || ($schema['additionalProperties'] ?? null) !== false
            || ($schema['required'] ?? null) !== ['action'] || ! is_array($schema['properties'] ?? null)) {
            return false;
        }

        $properties = $schema['properties'];
        if (($properties['action']['type'] ?? null) !== 'string'
            || ($properties['action']['enum'] ?? null) !== ['create', 'update']) {
            return false;
        }
        foreach (['post_type', 'status', 'title', 'content'] as $field) {
            if (($properties[$field]['type'] ?? null) !== 'string') {
                return false;
            }
        }

        return ($properties['operation_id']['type'] ?? null) === 'string'
            && ($properties['operation_id']['minLength'] ?? null) === 8
            && ($properties['operation_id']['maxLength'] ?? null) === 128;
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

    /** @return array<string,mixed> */
    private function safeDetails(WpAiBridgeTargetConnectionException|WpAiBridgeMcpException $exception): array
    {
        return [
            ...($exception instanceof WpAiBridgeMcpException
                ? $exception->details : $exception->diagnostics),
            // Preserve the actual Gateway/connector exception message for
            // authorized operator diagnostics, not as the public MCP message.
            'gateway_error_message' => $exception->getMessage(),
            'exception_class' => $exception::class,
        ];
    }

    /** @param array<string,mixed> $diagnostics
     * @return array<string, mixed>
     */
    private function failed(string $operation, ?Target $target, string $code, string $message, array $diagnostics = []): array
    {
        $reference = CorrelationId::current();
        // Preserve error.code compatibility, while recording a remote Tool
        // rejection with unconfirmed effects as unknown, never confirmed safe.
        $unknown = $code === 'outcome_unknown' || ($diagnostics['effect_unconfirmed'] ?? null) === true;
        $this->activity->record(
            $reference,
            $operation,
            $unknown ? 'unknown' : 'failure',
            $target,
            $code,
            $diagnostics,
        );

        $error = [
            'code' => $code,
            'message' => $message,
            'next_step' => OperationDiagnostics::nextStep($code),
        ];
        // Only a visible authorized Target with a downstream operation error
        // receives a lookup reference, not failed input or access probes.
        if ($target instanceof Target && ! in_array($code, [
            'forbidden', 'target_not_found', 'invalid_input', 'target_paused',
        ], true)) {
            $error['diagnostic_reference'] = $reference;
        }

        return ['ok' => false, 'error' => $error];
    }
}
