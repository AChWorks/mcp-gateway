<?php

namespace App\Application\Batch;

use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use Illuminate\Support\Facades\DB;

/** Exact approved peer and credential snapshot for SSH; no transport I/O. */
final class SshTargetBatchIdentity
{
    /** @param list<Target> $targets
     * @return array<string, list<string>|null>
     */
    public function parts(array $targets): array
    {
        if ($targets === []) {
            return [];
        }
        $ids = array_map(static fn (Target $target): string => (string) $target->getKey(), $targets);
        $configs = SshTargetConfig::query()->whereIn('target_record_id', $ids)->get()->keyBy('target_record_id');
        $credentials = DB::table('target_credentials')->whereIn('target_record_id', $ids)
            ->orderBy('purpose')->orderBy('id')
            ->get(['id', 'target_record_id', 'purpose', 'connector_type', 'encrypted_payload'])
            ->groupBy('target_record_id');

        $bindings = [];
        foreach ($targets as $target) {
            $id = (string) $target->getKey();
            $config = $configs->get($id);
            $rows = $credentials->get($id);
            if (! $config instanceof SshTargetConfig || $rows === null || $rows->isEmpty()) {
                $bindings[$id] = null;

                continue;
            }
            $parts = [SshTargetBinding::hash($target, $config)];
            foreach ($rows as $credential) {
                if ($credential->connector_type !== 'ssh_direct') {
                    $parts = [];
                    break;
                }
                $parts[] = (string) $credential->id;
                $parts[] = (string) $credential->purpose;
                // Rotating the actual SSH login secret invalidates old work.
                $parts[] = hash('sha256', (string) $credential->encrypted_payload);
            }
            $bindings[$id] = $parts === [] ? null : $parts;
        }

        return $bindings;
    }
}
