<?php

namespace App\Application\Targets;

use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * Database is the source of intent, not a filesystem transaction.
 *
 * The one-use claim is committed as "claimed" BEFORE a key is published.
 * Publication is atomic, and only a verified publication can mark claims
 * active or a revocation fully reconciled. A process crash leaves a durable
 * claimed/revoked + publication_pending receipt for Owner repair.
 */
class SshManagedReverseAuthorizedKeys
{
    private int $lockDepth = 0;

    public function __construct(private readonly TargetTransportBinding $bindings) {}

    private function filePath(): string
    {
        return (string) config('ssh.managed_reverse.authorized_keys_file');
    }

    /** @return array{version:int,control_port:int,control_user:string,control_host_key:string,authorized_keys_file:string}|null */
    public function hostManifest(): ?array
    {
        $file = (string) config('ssh.managed_reverse.host_manifest_file');
        // On shared/aaPanel PHP-FPM, open_basedir may exclude this root-owned
        // manifest. An unavailable host bootstrap is a fail-closed readiness
        // state, not an unhandled Laravel ErrorException or a reason to relax
        // the PHP restriction. Suppress filesystem warnings at this boundary;
        // every failed check is treated as an unavailable manifest.
        if (! @is_file($file) || @is_link($file) || ! @is_readable($file)) {
            return null;
        }
        $owner = @fileowner($file);
        $mode = @fileperms($file);
        if (! app()->environment('testing') && ($owner !== 0 || ! is_int($mode)
            || ($mode & 0022) !== 0)) {
            return null;
        }
        $contents = @file_get_contents($file);
        if (! is_string($contents)) {
            return null;
        }
        $decoded = json_decode($contents, true, 8);
        if (! is_array($decoded)
            || ($decoded['version'] ?? null) !== 1
            || ($decoded['authorized_keys_file'] ?? null) !== $this->filePath()
            || ! is_int($decoded['control_port'] ?? null)
            || ! is_string($decoded['control_user'] ?? null)
            || ! is_string($decoded['control_host_key'] ?? null)) {
            return null;
        }

        return $decoded;
    }

    public function matchesGateway(SshManagedReverseGateway $gateway): bool
    {
        $manifest = $this->hostManifest();

        return $manifest !== null
            && $manifest['control_port'] === $gateway->control_port
            && hash_equals($manifest['control_user'], $gateway->control_user)
            && hash_equals($manifest['control_host_key'], $gateway->control_host_key);
    }

    public function canPublish(): bool
    {
        $file = $this->filePath();

        return $this->hostManifest() !== null
            && @is_file($file) && ! @is_link($file) && @is_writable($file)
            && @is_dir(dirname($file)) && ! @is_link(dirname($file))
            && @is_writable(dirname($file));
    }

    /**
     * Serialize state mutations that can affect OpenSSH authorization across
     * concurrent PHP workers. No root privileges; lock is PHP-owned state.
     *
     * @template T
     *
     * @param  callable():T  $operation
     * @return T
     */
    public function withPolicyLock(callable $operation): mixed
    {
        if ($this->lockDepth > 0) {
            return $operation();
        }
        $file = $this->filePath().'.sync.lock';
        if (! $this->canPublish() || @is_link($file) || (@file_exists($file) && ! @is_file($file))) {
            throw new RuntimeException('Managed Reverse SSH policy lock or host reader is unsafe/unavailable.');
        }
        $handle = @fopen($file, 'c');
        if ($handle === false) {
            throw new RuntimeException('Cannot open managed Reverse SSH publication lock.');
        }
        try {
            if (! @flock($handle, LOCK_EX)) {
                throw new RuntimeException('Cannot lock managed Reverse SSH key publication.');
            }
            $this->lockDepth++;

            return $operation();
        } finally {
            $this->lockDepth = 0;
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /** @return array{contents:string,gateway_revision:int,gateway_enabled:bool,gateway_pending:bool,publish_enabled:bool,claimed_ids:list<string>,pending_ids:list<string>} */
    private function snapshot(bool $ownerReconciliation, ?string $claimId = null): array
    {
        $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
        if (! $gateway || ! $this->canPublish() || ! $this->matchesGateway($gateway)) {
            throw new RuntimeException('Managed Reverse SSH authorized-key host bootstrap is unavailable.');
        }
        // A scoped operation may remove keys, but must not restore a
        // globally pending Enable. Only an Owner publication can open it.
        // Read this decision under the same locked provider snapshot used
        // for the publication receipt, not from caller preflight state.
        $publishEnabled = $gateway->enabled && (! $gateway->publication_pending || $ownerReconciliation);
        $lines = [];
        $claimedIds = [];
        if ($publishEnabled) {
            $entries = SshManagedReverseEnrollment::query()
                ->whereNull('revoked_at')
                ->where(static function ($query) use ($ownerReconciliation, $claimId): void {
                    $query->where('state', 'active');
                    if ($ownerReconciliation || $claimId !== null) {
                        $query->orWhere(static function ($claimed) use ($ownerReconciliation, $claimId): void {
                            $claimed->where('state', 'claimed');
                            if (! $ownerReconciliation) {
                                $claimed->whereKey($claimId);
                            }
                        });
                    }
                })->orderBy('target_id')->lockForUpdate()->get();
            foreach ($entries as $entry) {
                if (! is_string($entry->control_public_key)
                    || ! str_starts_with($entry->control_public_key, 'ssh-ed25519 ')) {
                    throw new RuntimeException('Managed Reverse SSH enrollment has invalid key state.');
                }
                $lines[] = sprintf(
                    'restrict,port-forwarding,permitlisten="127.0.0.1:%d" %s',
                    $entry->listener_port,
                    $entry->control_public_key,
                );
                if ($entry->state === 'claimed' && $entry->publication_pending) {
                    $claimedIds[] = (string) $entry->getKey();
                }
            }
        }

        // An enrollment claim grants only its own activation. Unrelated
        // failed claims remain pending until the authorized Owner repair.
        // Removals/reissues can be reconciled without opening any claim.
        $pending = SshManagedReverseEnrollment::query()->where('publication_pending', true)
            ->where(static fn ($query) => $query->where('state', '!=', 'claimed')->orWhereIn('id', $claimedIds));

        return [
            'contents' => implode("\n", $lines).($lines ? "\n" : ''),
            'gateway_revision' => $gateway->revision,
            'gateway_enabled' => (bool) $gateway->enabled,
            'gateway_pending' => (bool) $gateway->publication_pending,
            'publish_enabled' => $publishEnabled,
            'claimed_ids' => $claimedIds,
            'pending_ids' => $pending->orderBy('id')->lockForUpdate()
                ->pluck('id')->all(),
        ];
    }

    /**
     * Writer seam for isolated fault injection. A rename error must never
     * silently count as an activated or fully reconciled enrollment.
     */
    protected function publish(string $contents): void
    {
        $path = $this->filePath();
        $temporary = $path.'.'.bin2hex(random_bytes(12)).'.tmp';
        if (@file_put_contents($temporary, $contents, LOCK_EX) === false) {
            throw new RuntimeException('Cannot stage Reverse SSH public-key policy.');
        }
        try {
            if (! @chmod($temporary, 0600) || ! @rename($temporary, $path)) {
                throw new RuntimeException('Cannot publish Reverse SSH public-key policy.');
            }
            if (@file_get_contents($path) !== $contents) {
                throw new RuntimeException('Published Reverse SSH policy does not match the committed intent.');
            }
        } finally {
            if (@is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    /** The reader must match current policy with no outstanding publishable transitions. */
    public function isReconciled(): bool
    {
        try {
            $snapshot = DB::transaction(fn (): array => $this->snapshot(true));

            return ! $snapshot['gateway_pending'] && $snapshot['pending_ids'] === []
                && @file_get_contents($this->filePath()) === $snapshot['contents'];
        } catch (\Throwable) {
            return false;
        }
    }

    /** Global Save/Repair is admitted by the Owner-only controller. */
    public function reconcileAsOwner(): void
    {
        $this->sync(true);
    }

    /** Closure and key removal never grant new route authority. */
    public function reconcileClosures(): void
    {
        $this->sync(false);
    }

    /** A one-use enrollment authorizes publication of its own claim only. */
    public function publishClaim(string $claimId): void
    {
        $this->sync(false, $claimId);
    }

    private function sync(bool $ownerReconciliation, ?string $claimId = null): void
    {
        $this->withPolicyLock(function () use ($ownerReconciliation, $claimId): void {
            // Committed intent is read in its own completed transaction.
            // No rollback after a rename can erase this durable intention.
            $snapshot = DB::transaction(fn (): array => $this->snapshot($ownerReconciliation, $claimId), 3);
            $this->publish($snapshot['contents']);
            // A failed/crashed finalization leaves claimed/revoked receipts;
            // an Owner can safely repeat the exact publication.
            DB::transaction(function () use ($snapshot, $ownerReconciliation, $claimId): void {
                // Bind the receipt to the provider revision even when
                // different intents have identical key bytes. Preserve the
                // gateway -> Target -> enrollment lock order for mutations.
                $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
                if ($gateway === null || $gateway->revision !== $snapshot['gateway_revision']
                    || (bool) $gateway->enabled !== $snapshot['gateway_enabled']
                    || (bool) $gateway->publication_pending !== $snapshot['gateway_pending']) {
                    throw new RuntimeException('Managed Reverse SSH policy changed during publication. Reconcile before use.');
                }
                $globalActivation = $snapshot['publish_enabled'] && $snapshot['gateway_pending'];
                if ($globalActivation || $snapshot['claimed_ids'] !== []) {
                    $this->bindings->activateManagedReverse($globalActivation, $snapshot['claimed_ids']);
                }
                $current = $this->snapshot($ownerReconciliation, $claimId);
                if ($current !== $snapshot || @file_get_contents($this->filePath()) !== $snapshot['contents']) {
                    throw new RuntimeException('Managed Reverse SSH policy changed during publication. Reconcile before use.');
                }
                // A closure-only receipt can reconcile Disable but cannot
                // consume a pending Enable receipt, even with exact bytes.
                if ($snapshot['gateway_pending'] && (! $snapshot['gateway_enabled'] || $globalActivation)) {
                    $gateway->forceFill(['publication_pending' => false])->save();
                }
                foreach ($snapshot['pending_ids'] as $id) {
                    $entry = SshManagedReverseEnrollment::query()->whereKey($id)->lockForUpdate()->firstOrFail();
                    $entry->forceFill(['publication_pending' => false])->save();
                    if ($entry->state === 'claimed') {
                        $entry->forceFill(['state' => 'active', 'activated_at' => now()])->save();
                    }
                }
            }, 3);
        });
    }
}
