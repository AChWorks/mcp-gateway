<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;
use App\Models\User;
use App\Support\CorrelationId;
use DateTimeInterface;
use InvalidArgumentException;

final readonly class TargetMcpToolHandlers
{
    public function __construct(
        private TargetInventory $inventory,
        private AccessControl $access,
        private ActivityRecorder $activity,
    ) {}

    /** @return array<string,mixed> */
    public function targetsList(
        User $user,
        ?string $cursor = null,
        int $limit = TargetInventory::MCP_DEFAULT_LIMIT,
        ?string $search = null,
        ?string $connection_state = null,
        ?string $connector_type = null,
    ): array {
        $correlationId = CorrelationId::current();

        if (! $this->access->allows($user, GatewayPermission::TargetsView)) {
            return $this->failure($correlationId, 'targets-list', 'forbidden',
                'The current Gateway user cannot view Targets.');
        }

        try {
            $page = $this->inventory->mcpPage($user, $cursor, $limit, $search, $connection_state, $connector_type);
        } catch (InvalidArgumentException) {
            return $this->failure($correlationId, 'targets-list', 'invalid_input',
                'The inventory filters or pagination arguments are invalid.');
        }

        $targets = [];
        foreach ($page['items'] as $target) {
            $state = $target->getAttribute('connection_state');
            $item = [
                'target_id' => $target->target_id,
                'display_name' => $target->display_name,
                'connector_type' => $target->connector_type,
                'connection_state' => $state instanceof TargetConnectionState ? $state->value : 'error',
            ];
            if ($target->connector_type === 'ssh_direct') {
                $item['ssh'] = SshTargetIdentity::safeMetadata($target);
            }
            $targets[] = $item;
        }

        $this->activity->record($correlationId, 'targets-list', 'success');

        return [
            'ok' => true,
            'targets' => $targets,
            'truncated' => $page['has_more'],
            'next_cursor' => $page['next_cursor'],
        ];
    }

    /** @return array<string,mixed> */
    public function targetContext(User $user, string $target_id): array
    {
        $correlationId = CorrelationId::current();
        $targetId = trim($target_id);

        if ($targetId === '' || strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            return $this->failure($correlationId, 'target-context', 'target_not_found',
                'The requested Target is not available.');
        }

        $target = $this->access
            ->scopeTargets(Target::query()->with('sshConfig'), $user, GatewayPermission::TargetsView)
            ->where('target_id', $targetId)
            ->first();

        if (! $target instanceof Target) {
            // An unauthorized identifier has the same response as an unknown one.
            return $this->failure($correlationId, 'target-context', 'target_not_found',
                'The requested Target is not available.');
        }

        $this->activity->record($correlationId, 'target-context', 'success', $target);

        $connectedAt = $target->getAttribute('connected_at');
        $state = $target->getAttribute('connection_state');

        $context = [
            'target_id' => $target->target_id,
            'display_name' => $target->display_name,
            'connector_type' => $target->connector_type,
            'connection_state' => $state instanceof TargetConnectionState ? $state->value : 'error',
            'last_error_code' => $target->last_error_code,
            'connected_at' => $connectedAt instanceof DateTimeInterface ? $connectedAt->format(DATE_ATOM) : null,
        ];
        if ($target->connector_type === 'ssh_direct') {
            $context['ssh'] = SshTargetIdentity::safeMetadata($target);
        }

        return ['ok' => true, 'target' => $context];
    }

    /** @return array<string,mixed> */
    private function failure(string $correlationId, string $operation, string $code, string $message): array
    {
        $this->activity->record($correlationId, $operation, 'failure', null, $code);

        // Internal correlation and request/client identifiers stay in Activity only.
        return ['ok' => false, 'error' => ['code' => $code, 'message' => $message]];
    }
}
