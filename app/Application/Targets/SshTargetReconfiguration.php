<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Support\CorrelationId;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use phpseclib4\Crypt\PublicKeyLoader;
use RuntimeException;
use Throwable;

final readonly class SshTargetReconfiguration
{
    public function __construct(
        private SshTargetVault $vault,
        private ActivityRecorder $activity,
        private SshReverseRoutePolicy $reverseRoutes,
        private TargetTransportBinding $transportBindings,
    ) {}

    public function revision(Target $target): string
    {
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();

        return $this->configurationRevision($target, $config, $this->credential($target));
    }

    /** @param array<string,mixed> $input */
    public function update(Target $target, array $input): bool
    {
        try {
            $endpoint = SshRegisteredEndpoint::fromInput(
                (string) $input['ssh_host'], (int) $input['ssh_port'], (string) $input['ssh_username'],
            );
            $pin = SshHostKeyPin::fromLine((string) $input['ssh_host_key']);
        } catch (InvalidArgumentException) {
            throw new TargetConnectorFailure(__('Check the SSH host, port, user and independently verified server public host key.'), 'ssh_host');
        }

        $routeMode = (string) ($input['ssh_route_mode'] ?? 'direct');
        $reversePort = isset($input['ssh_reverse_port']) && $input['ssh_reverse_port'] !== ''
            ? (int) $input['ssh_reverse_port'] : null;
        $tunnelIdentity = $input['ssh_tunnel_identity'] ?? null;
        $tunnelIdentity = $tunnelIdentity === '' ? null : $tunnelIdentity;
        if (! in_array($routeMode, ['direct', 'reverse'], true)
            || ($routeMode === 'direct' && ($reversePort !== null || $tunnelIdentity !== null))) {
            throw new TargetConnectorFailure(__('Select a valid SSH network route.'), 'ssh_route_mode');
        }

        $method = (string) $input['ssh_auth_method'];
        if (! in_array($method, ['password', 'private_key'], true)
            || ($input['ssh_trust_confirmed'] ?? null) !== 'yes') {
            throw new TargetConnectorFailure(__('Confirm the verified SSH server public host key before changing this Target.'), 'ssh_trust_confirmed');
        }

        $password = $input['ssh_password'] ?? null;
        $key = $input['ssh_private_key'] ?? null;
        $passphrase = $input['ssh_passphrase'] ?? null;
        if (($password !== null && $method !== 'password')
            || ($key !== null && $method !== 'private_key')
            || ($passphrase !== null && ($method !== 'private_key' || $key === null))) {
            throw new TargetConnectorFailure(__('Supply login material only for the selected method. A new key passphrase requires resubmitting the private key.'), 'ssh_auth_method');
        }

        return DB::transaction(function () use (
            $target, $input, $endpoint, $pin, $method, $password, $key, $passphrase,
            $routeMode, $reversePort, $tunnelIdentity,
        ): bool {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $config = SshTargetConfig::query()->where('target_record_id', $locked->getKey())->lockForUpdate()->firstOrFail();
            $routeChanged = $routeMode !== ($locked->usesReverseRoute() ? 'reverse' : 'direct')
                || $reversePort !== $locked->reverse_listener_port
                || $tunnelIdentity !== $locked->reverse_tunnel_identity;
            $managed = SshManagedReverseEnrollment::query()
                ->where('target_record_id', $locked->getKey())->first();
            // A managed listener forwards to the originally registered SSH
            // port. Revoke the actual old tunnel before changing that path
            // or port; ordinary credential changes do not affect it.
            if ($managed !== null && ($managed->state !== 'revoked' || $managed->publication_pending)
                && ($routeChanged || $endpoint->port !== $config->port)) {
                throw new TargetConnectorFailure(
                    __('Reconcile and revoke the old managed Reverse route before changing its network path or forwarded port. Stored SSH login credentials are independent.'),
                    'configuration', 'managed_reverse_reconfiguration_requires_revocation',
                );
            }
            if ($routeChanged && $routeMode === 'reverse') {
                try {
                    $route = $this->reverseRoutes->approve(
                        (string) $locked->target_id, $routeMode, $reversePort, $tunnelIdentity,
                    );
                    if ($route !== null) {
                        $this->reverseRoutes->assertPortAvailable($route, (string) $locked->getKey());
                    }
                } catch (SshTargetConnectionException $exception) {
                    throw new TargetConnectorFailure(
                        __('The selected Reverse listener or tunnel identity is not independently approved or is already assigned.'),
                        'ssh_reverse_port', $exception->reason,
                    );
                }
            }
            $credential = $this->credential($locked, lock: true);
            if ($locked->connector_type !== 'ssh_direct'
                || ! hash_equals(
                    (string) $input['configuration_revision'],
                    $this->configurationRevision($locked, $config, $credential),
                )) {
                throw new TargetConnectorFailure(__('The SSH Target changed since this form was opened. Reload and review the current settings.'), 'configuration_revision');
            }

            $identityChanged = $endpoint->host !== $config->host
                || $endpoint->port !== $config->port
                || $endpoint->username !== $config->username
                || $pin->canonicalLine() !== $config->pinned_host_key
                || $method !== $config->auth_method;
            $replacement = $method === 'password' ? $password : $key;
            $loginChanged = $identityChanged || $replacement !== null;
            $bindingChanged = $loginChanged || $routeChanged;
            $currentBindingRevision = (int) ($config->binding_revision ?? 0);
            if ($identityChanged && $currentBindingRevision >= 4294967295) {
                throw new TargetConnectorFailure(
                    __('The SSH binding revision is exhausted; do not reuse an older route or historical Job identity.'),
                    'configuration_revision',
                );
            }
            // This epoch fences endpoint/trust ABA, not credential material.
            // Replacement on the same endpoint is fenced independently by
            // the exact credential record and material at dispatch.
            $nextBindingRevision = $currentBindingRevision + ($identityChanged ? 1 : 0);

            if (! $bindingChanged) {
                return false;
            }
            if ($loginChanged) {
                if ($method !== $config->auth_method && $replacement === null) {
                    throw new TargetConnectorFailure(__('Changing the login method requires the new password or private key.'), 'ssh_auth_method');
                }
                // A delegated editor must not redirect a stored password to a new
                // server identity or login account. Port/route/hostname changes
                // that retain the exact verified key and username may retain it.
                if ($replacement === null && ($pin->canonicalLine() !== $config->pinned_host_key
                    || $endpoint->username !== $config->username)) {
                    throw new TargetConnectorFailure(__('Changing the verified server key or SSH username requires a new login credential.'), 'ssh_auth_method');
                }
                if (! $credential instanceof TargetCredential && $replacement === null) {
                    throw new TargetConnectorFailure(__('This Target has no SSH credential. Enter a new password or private key.'), 'ssh_auth_method');
                }

                $material = null;
                if ($credential instanceof TargetCredential) {
                    try {
                        $material = $this->vault->open($locked, $config, $credential);
                    } catch (Throwable) {
                        // Never overwrite an unreadable record-bound encrypted secret
                        // and pretend that an unknown encryption-key incident is benign.
                        throw new TargetConnectorFailure(__('Existing SSH encrypted credentials cannot be verified. Restore the matching Gateway encryption key before updating.'), 'ssh_auth_method');
                    }
                }
                $secret = $replacement ?? $material['secret'];
                $newPassphrase = $method === 'private_key'
                    ? ($replacement !== null ? $passphrase : ($material['passphrase'] ?? null))
                    : null;

                if ($method === 'private_key' && $replacement !== null) {
                    try {
                        PublicKeyLoader::loadPrivateKey($secret, $newPassphrase);
                    } catch (Throwable) {
                        throw new TargetConnectorFailure(__('The new SSH private key or passphrase is invalid.'), 'ssh_private_key');
                    }
                }

                // The vault seals against the NEW exact endpoint/auth/host-pin
                // binding. Do not reuse ciphertext from the old endpoint.
                $next = new SshTargetConfig([
                    'target_record_id' => $locked->getKey(),
                    'host' => $endpoint->host,
                    'port' => $endpoint->port,
                    'username' => $endpoint->username,
                    'auth_method' => $method,
                    'pinned_host_key' => $pin->canonicalLine(),
                    'binding_revision' => $nextBindingRevision,
                ]);
                try {
                    $encrypted = $this->vault->seal($locked, $next, $secret, $newPassphrase);
                } catch (RuntimeException) {
                    throw new TargetConnectorFailure(__('The new SSH credential is invalid.'), 'ssh_private_key');
                }

                if ($credential instanceof TargetCredential) {
                    if ($replacement !== null) {
                        $credential->supersedeAuthority($encrypted);
                    } else {
                        // Same verified account and host key: rebind the
                        // envelope, not the grant. Peer revision is separate.
                        $credential->forceFill(['encrypted_payload' => $encrypted])->save();
                    }
                } else {
                    TargetCredential::query()->create([
                        'target_record_id' => $locked->getKey(),
                        'connector_type' => 'ssh_direct',
                        'purpose' => SshTargetVault::PURPOSE,
                        'encrypted_payload' => $encrypted,
                    ]);
                }

                SshManagedReverseEnrollment::query()->where('target_record_id', $locked->getKey())
                    ->where('login_public_key', '!=', '')->update(['login_public_key' => '']);

            }

            if ($routeChanged) {
                $this->transportBindings->changeReverseLocked($locked, $reversePort, $tunnelIdentity);
            }

            // Config immutability is intentional outside this single audited,
            // Owner/password-gated, atomic rotation path. Query builder update
            // cannot trigger the normal Eloquent model-saving guard.
            DB::table('ssh_direct_target_configs')->where('id', $config->getKey())->update([
                'host' => $endpoint->host,
                'port' => $endpoint->port,
                'username' => $endpoint->username,
                'auth_method' => $method,
                'pinned_host_key' => $pin->canonicalLine(),
                'binding_revision' => $nextBindingRevision,
                'verification_attempt_id' => null,
                'observed_peer_ip' => null,
                'observed_at' => null,
                'updated_at' => now(),
            ]);
            $locked->forceFill($loginChanged ? [
                'connection_state' => TargetConnectionState::Disconnected,
                'last_error_code' => null,
                'last_tested_at' => null,
                'connected_at' => null,
                'last_success_at' => null,
                'last_failure_at' => null,
                'last_failure_code' => null,
            ] : ['last_tested_at' => null])->save();
            $this->activity->recordRequired(
                CorrelationId::current(), $loginChanged ? 'ssh-target-reconfigure' : 'ssh-target-route-reconfigure', 'success', $locked,
            );

            return true;
        });
    }

    private function configurationRevision(Target $target, SshTargetConfig $config, ?TargetCredential $credential): string
    {
        return TargetConfigurationRevision::make($target, [
            'host' => $config->host,
            'port' => $config->port,
            'username' => $config->username,
            'auth_method' => $config->auth_method,
            'pinned_host_key' => $config->pinned_host_key,
            'binding_revision' => $config->binding_revision,
            // This form also edits the selected manual Reverse route.
            'route' => $this->transportBindings->revision($target),
        ], $credential?->authorityFingerprint());
    }

    private function credential(Target $target, bool $lock = false): ?TargetCredential
    {
        $query = TargetCredential::query()
            ->where('target_record_id', $target->getKey())
            ->where('connector_type', 'ssh_direct')
            ->where('purpose', SshTargetVault::PURPOSE);

        return ($lock ? $query->lockForUpdate() : $query)->first();
    }
}
