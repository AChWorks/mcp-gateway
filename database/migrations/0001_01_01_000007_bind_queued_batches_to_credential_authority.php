<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        // Run during the quiescent application migration window. Rebind only
        // exact, never-dispatched queued snapshots. An unproven old digest
        // remains durable evidence and cannot match the new versioned
        // admission identity; the Worker requires fresh Preview/approval.
        // Keep the conversion self-contained, including both historical
        // formats, so future runtime changes cannot reinterpret this step.
        DB::table('targets')->whereExists(static function ($query): void {
            $query->selectRaw('1')->from('target_batch_items')
                ->whereColumn('target_record_id', 'targets.id')
                ->where('status', 'queued')->whereNull('dispatch_attempt_id');
        })->select('id')->chunkById(100, function ($targets): void {
            foreach ($targets as $record) {
                DB::transaction(function () use ($record): void {
                    $target = DB::table('targets')->where('id', $record->id)->lockForUpdate()->first();
                    if ($target === null) {
                        return;
                    }
                    $pair = $this->bindingPair($target);
                    if ($pair === null) {
                        return;
                    }
                    DB::table('target_batch_items')
                        ->where('target_record_id', $target->id)
                        ->where('target_id_snapshot', $target->target_id)
                        ->where('connector_type_snapshot', $target->connector_type)
                        ->where('status', 'queued')->whereNull('dispatch_attempt_id')
                        ->where('target_binding_hash', $pair[0])
                        ->update(['target_binding_hash' => $pair[1]]);
                }, 3);
            }
        });
    }

    /** @return array{string,string}|null */
    private function bindingPair(object $target): ?array
    {
        $record = (string) $target->id;
        $slug = (string) $target->target_id;
        $connector = (string) $target->connector_type;
        $routeEpoch = (int) $target->transport_revision;
        $relayId = $target->relay_record_id;
        $reversePort = $target->reverse_listener_port === null ? null : (int) $target->reverse_listener_port;
        $route = hash('sha256', json_encode([
            $record, $relayId, $reversePort, $target->reverse_tunnel_identity, $routeEpoch,
        ], JSON_THROW_ON_ERROR));
        $credentials = DB::table('target_credentials')->where('target_record_id', $record)
            ->orderBy('purpose')->orderBy('id')->lockForUpdate()->get();
        // The predecessor did not store a semantic grant revision. Do not
        // reinterpret an already superseded grant as authority for old work.
        if ($credentials->isEmpty() || $credentials->contains(
            static fn ($credential): bool => (int) $credential->authority_revision !== 0
                || $credential->connector_type !== $connector,
        )) {
            return null;
        }

        $old = [$record, $slug, $connector, (string) $relayId, (string) $routeEpoch];
        $new = ['target_batch_authority_v2', $record, $slug, $connector, $route];
        if ($connector === 'ssh_direct') {
            $config = DB::table('ssh_direct_target_configs')->where('target_record_id', $record)->lockForUpdate()->first();
            if ($config === null) {
                return null;
            }
            $peer = [
                $record, $slug, (string) $config->host, (string) $config->port,
                (string) $config->username, (string) $config->auth_method, (string) $config->pinned_host_key,
            ];
            $peerEpoch = (int) $config->binding_revision;
            $retained = $peer;
            if ($peerEpoch > 0 || $reversePort !== null) {
                $retained = [...$retained, $reversePort !== null ? 'reverse' : 'direct',
                    (string) $reversePort, (string) $target->reverse_tunnel_identity, (string) $peerEpoch];
            }
            if ($routeEpoch > 0 || $relayId !== null) {
                $retained = [...$retained, 'connection_relay', (string) $relayId, (string) $routeEpoch];
            }
            $old[] = hash('sha256', implode("\0", $retained));
            $new[] = hash('sha256', json_encode([
                ...$peer, (string) $config->id, (string) $config->target_record_id, $peerEpoch,
            ], JSON_THROW_ON_ERROR));
            foreach ($credentials as $credential) {
                if ($credential->purpose !== 'ssh_auth') {
                    return null;
                }
                $old = [...$old, (string) $credential->id, (string) $credential->purpose,
                    hash('sha256', (string) $credential->encrypted_payload)];
                $new = [...$new, (string) $credential->purpose, $this->grant($credential)];
            }
        } elseif ($connector === 'wp_ai_bridge') {
            if (DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $record)->exists()) {
                return null;
            }
            $config = DB::table('wp_ai_bridge_target_configs')->where('target_record_id', $record)->lockForUpdate()->first();
            if ($config === null) {
                return null;
            }
            foreach (['base_url', 'mcp_resource_url', 'oauth_issuer_url', 'oauth_token_url'] as $key) {
                $old[] = (string) $config->{$key};
                $new[] = (string) $config->{$key};
            }
            foreach ($credentials as $credential) {
                $metadata = DB::table('wp_ai_bridge_credential_metadata')
                    ->where('credential_id', $credential->id)->lockForUpdate()->first();
                if ($credential->purpose !== 'wordpress_oauth' || $metadata === null
                    || $metadata->resource_url !== $config->mcp_resource_url
                    || ! is_string($metadata->binding_hash) || $metadata->binding_hash === '') {
                    return null;
                }
                $consent = [(string) $metadata->client_id, (string) $metadata->resource_url, (string) $metadata->binding_hash];
                $old = [...$old, (string) $credential->id, (string) $credential->purpose, ...$consent];
                $new = [...$new, (string) $credential->purpose, $this->grant($credential), ...$consent];
            }
        } else {
            return null;
        }

        return [hash('sha256', implode("\0", $old)), hash('sha256', json_encode($new, JSON_THROW_ON_ERROR))];
    }

    private function grant(object $credential): string
    {
        return hash('sha256', (string) $credential->id."\0".(string) $credential->authority_revision);
    }

    public function down(): void
    {
        throw new RuntimeException('Restore the pre-update database to roll back queued authority conversion without reviving obsolete admissions.');
    }
};
