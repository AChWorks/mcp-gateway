<?php

namespace App\Application\Batch;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use Illuminate\Support\Facades\DB;

/** Exact non-secret transport/credential identity, with batched preview I/O. */
final class TargetBatchBinding
{
    public function hash(Target $target): ?string
    {
        return $this->hashMany([$target])[(string) $target->target_id] ?? null;
    }

    /**
     * Load only explicitly scoped Targets, in short bounded DB pages. A fleet
     * preview does not do N+1 credential/config/consent queries per Target.
     *
     * @param  list<Target>  $targets
     * @return array<string, string|null> Exact registered Target IDs to binding digest
     */
    public function hashMany(array $targets): array
    {
        $hashes = [];
        foreach (array_chunk($targets, 250) as $page) {
            $ids = array_map(static fn (Target $target): string => (string) $target->getKey(), $page);
            $sshConfigs = SshTargetConfig::query()->whereIn('target_record_id', $ids)
                ->get()->keyBy('target_record_id');
            $wordpressConfigs = WpAiBridgeTargetConfig::query()->whereIn('target_record_id', $ids)
                ->get()->keyBy('target_record_id');
            $credentials = DB::table('target_credentials')->whereIn('target_record_id', $ids)
                ->orderBy('purpose')->get(['id', 'target_record_id', 'purpose', 'connector_type', 'encrypted_payload'])
                ->groupBy('target_record_id');
            $wordPressCredentialIds = [];
            foreach ($credentials as $rows) {
                foreach ($rows as $credential) {
                    if ($credential->connector_type === 'wp_ai_bridge') {
                        $wordPressCredentialIds[] = $credential->id;
                    }
                }
            }
            $wpMeta = collect();
            foreach (array_chunk($wordPressCredentialIds, 250) as $metadataPage) {
                foreach (DB::table('wp_ai_bridge_credential_metadata')
                    ->whereIn('credential_id', $metadataPage)->get() as $row) {
                    $wpMeta->put($row->credential_id, $row);
                }
            }
            foreach ($page as $target) {
                $targetId = (string) $target->target_id;
                $recordId = (string) $target->getKey();
                if ($target->getAttribute('connection_state') !== TargetConnectionState::Connected
                    || $target->operations_paused) {
                    $hashes[$targetId] = null;

                    continue;
                }
                $config = match ($target->connector_type) {
                    'ssh_direct' => $sshConfigs->get($recordId),
                    'wp_ai_bridge' => $wordpressConfigs->get($recordId),
                    default => null,
                };
                $rows = $credentials->get($recordId);
                if ((! $config instanceof SshTargetConfig && ! $config instanceof WpAiBridgeTargetConfig)
                    || $rows === null || $rows->isEmpty()) {
                    $hashes[$targetId] = null;

                    continue;
                }
                $parts = [
                    $recordId, $targetId, (string) $target->connector_type,
                    (string) $target->getAttribute('relay_record_id'),
                    (string) $target->getAttribute('relay_binding_revision'),
                ];
                if ($config instanceof SshTargetConfig) {
                    $parts[] = SshTargetBinding::hash($target, $config);
                } else {
                    foreach (['base_url', 'mcp_resource_url', 'oauth_issuer_url', 'oauth_token_url'] as $key) {
                        $parts[] = (string) $config->getAttribute($key);
                    }
                }
                $valid = true;
                foreach ($rows as $credential) {
                    if ($credential->connector_type !== $target->connector_type) {
                        $valid = false;
                        break;
                    }
                    $parts[] = (string) $credential->id;
                    $parts[] = (string) $credential->purpose;
                    if ($config instanceof WpAiBridgeTargetConfig) {
                        // Token ciphertext and generation may rotate during
                        // ordinary OAuth refresh. Consent binding/identity may not.
                        $metadata = $wpMeta->get($credential->id);
                        if ($metadata === null || $metadata->resource_url !== $config->mcp_resource_url
                            || ! is_string($metadata->binding_hash) || $metadata->binding_hash === '') {
                            $valid = false;
                            break;
                        }
                        $parts[] = (string) $metadata->client_id;
                        $parts[] = (string) $metadata->resource_url;
                        $parts[] = (string) $metadata->binding_hash;
                    } else {
                        // SSH secret replacement changes the binding. Neither
                        // ciphertext nor private keys go into durable journals.
                        $parts[] = hash('sha256', (string) $credential->encrypted_payload);
                    }
                }
                $hashes[$targetId] = $valid ? hash('sha256', implode("\0", $parts)) : null;
            }
        }

        return $hashes;
    }
}
