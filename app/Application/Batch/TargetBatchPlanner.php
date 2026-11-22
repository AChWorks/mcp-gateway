<?php

namespace App\Application\Batch;

use App\Application\Access\AccessControl;
use App\Domain\Targets\Target;
use App\Models\User;
use InvalidArgumentException;

/** Read-only selection, authorization, exact identity proof and approval token. */
final readonly class TargetBatchPlanner
{
    public function __construct(
        private AccessControl $access,
        private DeferredBatchAuthority $authority,
        private BatchProviderResolver $providers,
        private TargetBatchBinding $bindings,
    ) {}

    /**
     * @param  array<string,mixed>  $origin  An already verified entry channel
     * @param  array<mixed>  $targetIds
     * @param  array<string,mixed>  $arguments
     * @return array<string,mixed>
     */
    public function preview(
        User $user, array $origin, string $capability, array $targetIds,
        array $arguments, string $mode, bool $stopOnFailure, int $parallelism,
    ): array {
        $provider = $this->providers->find($capability);
        if ($provider === null || ! $provider->validArguments($arguments)) {
            throw new InvalidArgumentException('Unsupported Batch capability or invalid bounded arguments.');
        }
        if (! in_array($mode, ['concurrent', 'rolling'], true)
            || $parallelism < 1 || $parallelism > max(1, (int) config('batch.max_parallelism', 4))) {
            throw new InvalidArgumentException('Invalid Batch execution mode or Owner-configured parallelism.');
        }
        if ($targetIds === [] || ! array_is_list($targetIds)) {
            throw new InvalidArgumentException('Batch requires an explicit nonempty Target selection.');
        }
        $ids = [];
        foreach ($targetIds as $id) {
            if (! is_string($id) || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $id) !== 1) {
                throw new InvalidArgumentException('Batch Target IDs must be valid exact registered identifiers.');
            }
            $ids[$id] = true;
        }
        $ids = array_keys($ids);
        $currentUser = User::query()->find($user->getKey());
        if (! $currentUser instanceof User || ! $this->authority->allows(
            (object) ['actor_user_id' => (int) $user->getKey(), ...$origin], $currentUser,
        )) {
            throw new InvalidArgumentException('Batch origin or current user authorization is no longer valid.');
        }

        // Chunk to avoid driver parameter ceilings. No in-memory fleet scan or
        // hidden "all Targets" option: only the explicitly selected IDs.
        $targets = [];
        foreach (array_chunk($ids, 250) as $page) {
            // One canonical DB policy per selection page, not separate
            // permission/group/deny lookups for every fleet Target. This is
            // the exact policy also rechecked at child execution time.
            $authorized = $this->access->scopeTargets(
                Target::query()->whereIn('target_id', $page), $currentUser, $provider->permission(),
            );
            foreach ($authorized->get() as $target) {
                $targets[$target->target_id] = $target;
            }
        }
        $bindings = $this->bindings->hashMany(array_values($targets));
        $items = [];
        foreach ($ids as $id) {
            $target = $targets[$id] ?? null;
            $state = 'queued';
            $error = null;
            $binding = null;
            $recordId = null;
            $connector = null;
            if (! $target instanceof Target) {
                $state = 'blocked';
                $error = 'target_not_found';
            } else {
                $recordId = (string) $target->getKey();
                $connector = $target->connector_type;
                if ($connector !== $provider->connectorType()) {
                    $state = 'blocked';
                    $error = 'unsupported_connector';
                } else {
                    $binding = $bindings[$id] ?? null;
                    if ($binding === null) {
                        $state = 'blocked';
                        $error = $target->operations_paused ? 'target_paused' : 'target_unavailable';
                    }
                }
            }
            $items[] = [
                'target_id' => $id,
                'target_record_id' => $recordId,
                'connector_type' => $connector,
                'binding_hash' => $binding,
                'status' => $state,
                'error_code' => $error,
            ];
        }
        $ready = count(array_filter($items, static fn (array $row): bool => $row['status'] === 'queued'));
        $fingerprint = hash('sha256', json_encode([
            $user->getKey(), $origin['client_identity_hash'] ?? null, $origin['source_channel'] ?? null,
            $origin['authorization_id'] ?? null, $capability, $arguments, $mode,
            $stopOnFailure, $parallelism, $items,
        ], JSON_THROW_ON_ERROR));
        $expires = time() + 600;
        $approval = $expires.'.'.hash_hmac('sha256', $expires.'|'.$fingerprint, (string) config('app.key'));

        return [
            'ok' => true,
            'capability' => $provider->key(),
            'effectful' => $provider->isEffectful(),
            'execution_mode' => $mode,
            'stop_on_failure' => $stopOnFailure,
            'parallelism' => $parallelism,
            'selected_count' => count($items),
            'eligible_count' => $ready,
            'items' => $items,
            'fingerprint' => $fingerprint,
            'preview_token' => $approval,
            'expires_at' => gmdate('c', $expires),
        ];
    }

    /**
     * Immutable, caller-supplied intent for recovering an already accepted
     * request_id. Target permissions, credentials and Preview expiry are
     * deliberately NOT inputs: those can change after admission.
     *
     * @param  array<string,mixed>  $origin
     * @param  array<mixed>  $targetIds
     * @param  array<string,mixed>  $arguments
     */
    public function requestIntent(
        User $user, array $origin, string $capability, array $targetIds,
        array $arguments, string $mode, bool $stopOnFailure, int $parallelism,
    ): string {
        if ($targetIds === [] || ! array_is_list($targetIds)) {
            throw new InvalidArgumentException('Batch requires a nonempty exact Target selection.');
        }
        $ids = [];
        foreach ($targetIds as $id) {
            if (! is_string($id) || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $id) !== 1) {
                throw new InvalidArgumentException('Batch Target identifiers are invalid.');
            }
            $ids[$id] = true;
        }

        return hash('sha256', json_encode([
            'batch_request_intent_v1', (string) $user->getKey(),
            $origin['source_channel'] ?? null, $origin['client_identity_hash'] ?? null,
            $origin['authorization_id'] ?? null, $origin['client_profile_generation'] ?? null,
            $origin['resource_hash'] ?? null,
            $capability, array_keys($ids), $arguments, $mode, $stopOnFailure, $parallelism,
        ], JSON_THROW_ON_ERROR));
    }

    public function tokenValid(string $token, string $fingerprint): bool
    {
        if (preg_match('/^([0-9]{10})\.([a-f0-9]{64})$/D', $token, $matches) !== 1) {
            return false;
        }
        $expires = (int) $matches[1];
        if ($expires < time() || $expires > time() + 600) {
            return false;
        }

        return hash_equals(hash_hmac('sha256', $expires.'|'.$fingerprint, (string) config('app.key')), $matches[2]);
    }
}
