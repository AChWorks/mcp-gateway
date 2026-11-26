<?php

namespace App\Application\Batch;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;

/** SSH peer/trust and semantic grant; exact material is checked at actual dispatch. */
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
        $credentials = TargetCredential::query()->whereIn('target_record_id', $ids)
            ->where('connector_type', 'ssh_direct')->where('purpose', SshTargetVault::PURPOSE)
            ->get(['id', 'target_record_id', 'purpose', 'authority_revision'])
            ->keyBy('target_record_id');

        $bindings = [];
        foreach ($targets as $target) {
            $id = (string) $target->getKey();
            $config = $configs->get($id);
            $credential = $credentials->get($id);
            if (! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
                $bindings[$id] = null;

                continue;
            }
            $bindings[$id] = [SshTargetBinding::peerFingerprint($target, $config),
                (string) $credential->purpose, $credential->authorityFingerprint()];
        }

        return $bindings;
    }
}
