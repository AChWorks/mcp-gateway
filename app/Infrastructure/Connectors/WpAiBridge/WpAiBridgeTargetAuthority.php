<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use Illuminate\Support\Facades\DB;

/** OAuth consent/client binding survives legitimate access/refresh rotation. */
final class WpAiBridgeTargetAuthority
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
        $credentials = TargetCredential::query()->whereIn('target_record_id', $ids)
            ->whereNotExists(static function ($query): void {
                $query->selectRaw('1')->from('wp_ai_bridge_revocation_intents')
                    ->whereColumn('wp_ai_bridge_revocation_intents.target_record_id', 'target_credentials.target_record_id');
            })
            ->where('connector_type', 'wp_ai_bridge')->where('purpose', WpAiBridgeTargetVault::PURPOSE)
            ->get(['id', 'target_record_id', 'purpose', 'authority_revision'])
            ->keyBy('target_record_id');
        $credentialIds = $credentials->pluck('id')->all();
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
            $credential = $credentials->get($id);
            if (! $config instanceof WpAiBridgeTargetConfig || ! $credential instanceof TargetCredential) {
                $bindings[$id] = null;

                continue;
            }
            $credentialMeta = $metadata->get($credential->id);
            if ($credentialMeta === null || $credentialMeta->resource_url !== $config->mcp_resource_url
                || ! is_string($credentialMeta->binding_hash) || $credentialMeta->binding_hash === '') {
                $bindings[$id] = null;

                continue;
            }
            $parts = [];
            foreach (['base_url', 'mcp_resource_url', 'oauth_issuer_url', 'oauth_token_url'] as $key) {
                $parts[] = (string) $config->getAttribute($key);
            }
            $bindings[$id] = [...$parts, (string) $credential->purpose, $credential->authorityFingerprint(),
                (string) $credentialMeta->client_id, (string) $credentialMeta->resource_url, (string) $credentialMeta->binding_hash];
        }

        return $bindings;
    }
}
