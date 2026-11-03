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
            && is_file($file) && ! is_link($file) && is_writable($file)
            && is_dir(dirname($file)) && ! is_link(dirname($file))
            && is_writable(dirname($file));
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
        if (! $this->canPublish() || is_link($file) || (file_exists($file) && ! is_file($file))) {
            throw new RuntimeException('Managed Reverse SSH policy lock or host reader is unsafe/unavailable.');
        }
        $handle = fopen($file, 'c');
        if ($handle === false) {
            throw new RuntimeException('Cannot open managed Reverse SSH publication lock.');
        }
        try {
            if (! flock($handle, LOCK_EX)) {
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

    /** @return array{contents:string,gateway_pending:bool,pending_ids:list<string>} */
    private function snapshot(): array
    {
        $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
        if (! $gateway || ! $this->canPublish() || ! $this->matchesGateway($gateway)) {
            throw new RuntimeException('Managed Reverse SSH authorized-key host bootstrap is unavailable.');
        }
        $entries = SshManagedReverseEnrollment::query()
            ->whereIn('state', ['claimed', 'active'])
            ->whereNull('revoked_at')->orderBy('target_id')->lockForUpdate()->get();
        $lines = [];
        if ($gateway->enabled) {
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
            }
        }

        return [
            'contents' => implode("\n", $lines).($lines ? "\n" : ''),
            'gateway_pending' => (bool) $gateway->publication_pending,
            'pending_ids' => SshManagedReverseEnrollment::query()
                ->where('publication_pending', true)->orderBy('id')->lockForUpdate()
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
        if (file_put_contents($temporary, $contents, LOCK_EX) === false) {
            throw new RuntimeException('Cannot stage Reverse SSH public-key policy.');
        }
        try {
            if (! chmod($temporary, 0600) || ! rename($temporary, $path)) {
                throw new RuntimeException('Cannot publish Reverse SSH public-key policy.');
            }
            if (file_get_contents($path) !== $contents) {
                throw new RuntimeException('Published Reverse SSH policy does not match the committed intent.');
            }
        } finally {
            if (is_file($temporary)) {
                unlink($temporary);
            }
        }
    }

    /** The current reader must agree with durable admission policy and have no outstanding transitions. */
    public function isReconciled(): bool
    {
        if (! $this->canPublish() || SshManagedReverseGateway::query()
            ->where('publication_pending', true)->exists() || SshManagedReverseEnrollment::query()
            ->where('publication_pending', true)->exists()) {
            return false;
        }
        try {
            $expected = DB::transaction(fn (): string => $this->snapshot()['contents']);

            return file_get_contents($this->filePath()) === $expected;
        } catch (\Throwable) {
            return false;
        }
    }

    public function sync(): void
    {
        $this->withPolicyLock(function (): void {
            // Committed intent is read in its own completed transaction.
            // No rollback after a rename can erase this durable intention.
            $snapshot = DB::transaction(fn (): array => $this->snapshot(), 3);
            $this->publish($snapshot['contents']);
            // A failed/crashed finalization leaves claimed/revoked receipts;
            // an Owner can safely repeat the exact publication.
            DB::transaction(function () use ($snapshot): void {
                $current = $this->snapshot();
                if ($current !== $snapshot || file_get_contents($this->filePath()) !== $snapshot['contents']) {
                    throw new RuntimeException('Managed Reverse SSH policy changed during publication. Reconcile before use.');
                }
                if ($snapshot['gateway_pending']) {
                    SshManagedReverseGateway::query()->whereKey(1)->update(['publication_pending' => false]);
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
