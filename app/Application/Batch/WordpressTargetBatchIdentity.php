<?php

namespace App\Application\Batch;

use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use Illuminate\Support\Facades\DB;

/** OAuth consent/client binding survives legitimate access/refresh rotation. */
final class WordpressTargetBatchIdentity
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
        $configs = WpAiBridgeTargetConfig::query()->whereIn('target_record_id', $ids)->get()->keyBy('target_record_id');
        $credentials = DB::table('target_credentials')->whereIn('target_record_id', $ids)
            ->orderBy('purpose')->orderBy('id')
            ->get(['id', 'target_record_id', 'purpose', 'connector_type'])
            ->groupBy('target_record_id');
        $credentialIds = $credentials->flatten(1)->pluck('id')->all();
        $metadata = collect();
        foreach (array_chunk($credentialIds, 250) as $page) {
            foreach (DB::table('wp_ai_bridge_credential_metadata')->whereIn('credential_id', $page)->get() as $row) {
                $metadata->put($row->credential_id, $row);
            }
        }

        $bindings = [];
        foreach ($targets as $target) {
            $id = (string) $target->getKey();
            $config = $configs->get($id);
            $rows = $credentials->get($id);
            if (! $config instanceof WpAiBridgeTargetConfig || $rows === null || $rows->isEmpty()) {
                $bindings[$id] = null;

                continue;
            }
            $parts = [];
            foreach (['base_url', 'mcp_resource_url', 'oauth_issuer_url', 'oauth_token_url'] as $key) {
                $parts[] = (string) $config->getAttribute($key);
            }
            foreach ($rows as $credential) {
                $credentialMeta = $metadata->get($credential->id);
                if ($credential->connector_type !== 'wp_ai_bridge'
                    || $credentialMeta === null
                    || $credentialMeta->resource_url !== $config->mcp_resource_url
                    || ! is_string($credentialMeta->binding_hash) || $credentialMeta->binding_hash === '') {
                    $parts = [];
                    break;
                }
                $parts[] = (string) $credential->id;
                $parts[] = (string) $credential->purpose;
                $parts[] = (string) $credentialMeta->client_id;
                $parts[] = (string) $credentialMeta->resource_url;
                $parts[] = (string) $credentialMeta->binding_hash;
            }
            $bindings[$id] = $parts === [] ? null : $parts;
        }

        return $bindings;
    }
}
