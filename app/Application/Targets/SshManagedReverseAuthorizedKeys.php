<?php

namespace App\Application\Targets;

use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * Publishes ONLY restricted public keys into the dedicated host-provisioned
 * reader file. No root execution or sshd editing from a PHP request.
 */
final class SshManagedReverseAuthorizedKeys
{
    private function filePath(): string
    {
        return (string) config('ssh.managed_reverse.authorized_keys_file');
    }

    /** @return array{version:int,control_port:int,control_user:string,control_host_key:string,authorized_keys_file:string}|null */
    public function hostManifest(): ?array
    {
        $file = (string) config('ssh.managed_reverse.host_manifest_file');
        if (! is_file($file) || is_link($file) || ! is_readable($file)) {
            return null;
        }
        $owner = fileowner($file);
        $mode = fileperms($file);
        if (! app()->environment('testing') && ($owner !== 0 || ! is_int($mode)
            || ($mode & 0022) !== 0)) {
            return null;
        }
        $decoded = json_decode((string) file_get_contents($file), true, 8);
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
            && is_dir(dirname($file)) && ! is_link(dirname($file));
    }

    public function sync(): void
    {
        DB::transaction(function (): void {
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
            $path = $this->filePath();
            $temporary = $path.'.'.bin2hex(random_bytes(12)).'.tmp';
            if (file_put_contents($temporary, implode("\n", $lines).($lines ? "\n" : ''), LOCK_EX) === false) {
                throw new RuntimeException('Cannot stage Reverse SSH public-key policy.');
            }
            try {
                chmod($temporary, 0600);
                if (! rename($temporary, $path)) {
                    throw new RuntimeException('Cannot publish Reverse SSH public-key policy.');
                }
            } finally {
                if (is_file($temporary)) {
                    unlink($temporary);
                }
            }
            foreach ($entries as $entry) {
                if ($entry->state === 'claimed' && $gateway->enabled) {
                    $entry->forceFill(['state' => 'active', 'activated_at' => now()])->save();
                }
            }
        }, 3);
    }
}
