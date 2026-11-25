<?php

namespace App\Application\Batch;

use App\Application\Targets\TargetConnectorRegistry;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;

/** Shared eligibility/identity fence; no connector-specific credential schema. */
final readonly class TargetBatchBinding
{
    public function __construct(private TargetConnectorRegistry $connectors) {}

    public function hash(Target $target): ?string
    {
        return $this->hashMany([$target])[(string) $target->target_id] ?? null;
    }

    /**
     * Read only the explicitly selected, currently available Targets in
     * bounded pages. An unsupported connector never inherits another one's
     * binding rules or receives an optimistic generic hash.
     *
     * @param  list<Target>  $targets
     * @return array<string, string|null> Exact registered Target IDs to digest
     */
    public function hashMany(array $targets): array
    {
        $hashes = [];
        foreach (array_chunk($targets, 250) as $page) {
            $groups = [];
            foreach ($page as $target) {
                $id = (string) $target->target_id;
                if ($target->getAttribute('connection_state') !== TargetConnectionState::Connected || $target->operations_paused) {
                    $hashes[$id] = null;

                    continue;
                }
                $groups[$target->connector_type][] = $target;
            }
            foreach ($groups as $selected) {
                $connector = $this->connectors->availableForTarget($selected[0]);
                $partsByRecord = $connector instanceof TargetBatchBindingContributor
                    ? $connector->batchBindingParts($selected) : [];
                foreach ($selected as $target) {
                    $id = (string) $target->target_id;
                    $recordId = (string) $target->getKey();
                    $connectorParts = $partsByRecord[$recordId] ?? null;
                    if (! is_array($connectorParts) || $connectorParts === []) {
                        $hashes[$id] = null;

                        continue;
                    }
                    $common = [
                        $recordId, $id, (string) $target->connector_type,
                        (string) $target->getAttribute('relay_record_id'),
                        (string) $target->getAttribute('transport_revision'),
                    ];
                    $hashes[$id] = hash('sha256', implode("\0", [...$common, ...$connectorParts]));
                }
            }
        }

        return $hashes;
    }
}
