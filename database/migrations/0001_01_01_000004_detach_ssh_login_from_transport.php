<?php

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        // Released v3 envelopes included transport/job epochs in their
        // credential digest. Convert only exact verified old bindings; the
        // runtime has a single transport-independent format. Unchanged
        // Direct envelopes already have the canonical digest.
        DB::transaction(function (): void {
            $vault = app(SshTargetVault::class);
            TargetCredential::query()->where('connector_type', 'ssh_direct')
                ->where('purpose', SshTargetVault::PURPOSE)
                ->chunkById(100, function ($credentials) use ($vault): void {
                    foreach ($credentials as $credential) {
                        $target = Target::query()->whereKey($credential->target_record_id)->lockForUpdate()->firstOrFail();
                        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
                        try {
                            try {
                                $vault->open($target, $config, $credential);

                                continue;
                            } catch (RuntimeException) {
                                // Try exactly the released envelope, not an
                                // arbitrary historical route or another peer.
                            }
                            $payload = json_decode(Crypt::decryptString((string) $credential->encrypted_payload), true, 16, JSON_THROW_ON_ERROR);
                            $parts = $this->releasedBindingParts($target, $config,
                                SshHostKeyPin::fromLine($config->pinned_host_key)->canonicalLine());
                            if (! is_array($payload) || ($payload['v'] ?? null) !== 1
                                || $target->connector_type !== 'ssh_direct'
                                || ($payload['target_record_id'] ?? null) !== (string) $target->getKey()
                                || ($payload['target_id'] ?? null) !== $target->target_id
                                || ($payload['connector_type'] ?? null) !== 'ssh_direct'
                                || ($payload['purpose'] ?? null) !== SshTargetVault::PURPOSE
                                || ($payload['auth_method'] ?? null) !== $config->auth_method
                                || ! hash_equals(hash('sha256', implode("\0", $parts)), (string) ($payload['binding'] ?? ''))
                                || ! is_string($payload['secret'] ?? null)
                                || (($payload['passphrase'] ?? null) !== null && ! is_string($payload['passphrase']))) {
                                throw new RuntimeException('Legacy SSH binding cannot be verified.');
                            }
                            // Re-encryption is not a credential or route change. Preserve
                            // exact admitted queued Batch bindings, not stale or dispatched
                            // journal evidence. The old hash uses the released raw host pin,
                            // whereas the verified vault envelope uses its canonical form.
                            $oldBatchBinding = $this->releasedBatchBinding($target, $config);
                            $credential->forceFill(['encrypted_payload' => $vault->seal(
                                $target, $config, $payload['secret'], $payload['passphrase'] ?? null,
                            )])->save();
                            if ($oldBatchBinding !== null) {
                                $newBatchBinding = $this->releasedBatchBinding($target, $config);
                                if ($newBatchBinding === null) {
                                    throw new RuntimeException('SSH Batch identity changed during credential conversion.');
                                }
                                DB::table('target_batch_items')->where('target_record_id', $target->getKey())
                                    ->where('target_id_snapshot', $target->target_id)
                                    ->where('connector_type_snapshot', 'ssh_direct')
                                    ->where('status', 'queued')->whereNull('dispatch_attempt_id')
                                    ->where('target_binding_hash', $oldBatchBinding)
                                    ->update(['target_binding_hash' => $newBatchBinding]);
                            }
                        } catch (Throwable $error) {
                            // Do not erase or silently reinterpret unreadable
                            // credentials. Roll back the data conversion.
                            throw new RuntimeException('Cannot migrate SSH login for Target '.$target->target_id.'. Check the underlying migration error before retrying the update.', previous: $error);
                        }
                    }
                });

            DB::table('ssh_reverse_managed_enrollments')->where(function ($query): void {
                $query->where('state', 'revoked')->orWhereExists(static function ($target): void {
                    $target->selectRaw('1')->from('targets')
                        ->whereColumn('targets.id', 'ssh_reverse_managed_enrollments.target_record_id')
                        ->where(static fn ($verified) => $verified->whereNotNull('connected_at')->orWhere('connection_state', 'connected'));
                })->orWhereNotExists(static function ($credential): void {
                    $credential->selectRaw('1')->from('target_credentials')
                        ->whereColumn('target_credentials.target_record_id', 'ssh_reverse_managed_enrollments.target_record_id')
                        ->where('connector_type', 'ssh_direct')->where('purpose', 'ssh_auth');
                });
            })->update(['login_public_key' => '']);
        });
    }

    /**
     * Exact v3.0.x queued SSH Batch identity. The route columns still belong
     * to the released schema at this migration step. The next migration
     * moves them without changing this digest's non-credential components.
     */
    private function releasedBatchBinding(Target $target, SshTargetConfig $config): ?string
    {
        if (! DB::table('target_batch_items')->where('target_record_id', $target->getKey())
            ->where('status', 'queued')->whereNull('dispatch_attempt_id')->exists()) {
            return null;
        }
        $parts = $this->releasedBindingParts($target, $config, (string) $config->pinned_host_key);
        $relayEpoch = (int) $target->relay_binding_revision;
        $common = [
            (string) $target->getKey(), (string) $target->target_id, (string) $target->connector_type,
            (string) $target->relay_record_id, (string) $relayEpoch,
            hash('sha256', implode("\0", $parts)),
        ];
        foreach (DB::table('target_credentials')->where('target_record_id', $target->getKey())
            ->orderBy('purpose')->orderBy('id')->get(['id', 'purpose', 'connector_type', 'encrypted_payload']) as $row) {
            if ($row->connector_type !== 'ssh_direct') {
                return null;
            }
            $common[] = (string) $row->id;
            $common[] = (string) $row->purpose;
            $common[] = hash('sha256', (string) $row->encrypted_payload);
        }

        return hash('sha256', implode("\0", $common));
    }

    /** @return list<string> */
    private function releasedBindingParts(Target $target, SshTargetConfig $config, string $hostPin): array
    {
        $parts = [
            (string) $target->getKey(), (string) $target->target_id,
            (string) $config->host, (string) $config->port, (string) $config->username,
            (string) $config->auth_method, $hostPin,
        ];
        $epoch = (int) ($config->binding_revision ?? 0);
        if ($epoch > 0 || ($config->route_mode ?? 'direct') !== 'direct') {
            $parts = [...$parts, (string) ($config->route_mode ?? 'direct'),
                (string) $config->reverse_listener_port, (string) $config->reverse_tunnel_identity, (string) $epoch];
        }
        $relayEpoch = (int) $target->relay_binding_revision;
        if ($relayEpoch > 0 || $target->relay_record_id !== null) {
            $parts = [...$parts, 'connection_relay', (string) $target->relay_record_id, (string) $relayEpoch];
        }

        return $parts;
    }

    public function down(): void
    {
        throw new RuntimeException('Restore the pre-update database and matching application key to roll back SSH credential conversion.');
    }
};
