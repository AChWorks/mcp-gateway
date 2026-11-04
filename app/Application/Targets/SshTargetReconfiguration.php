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
    ) {}

    public function revision(Target $target): string
    {
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();

        return TargetConfigurationRevision::make($target, $config->getAttributes(), $this->credential($target));
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

        try {
            $route = $this->reverseRoutes->approve(
                (string) $target->target_id, (string) ($input['ssh_route_mode'] ?? 'direct'),
                $input['ssh_reverse_port'] ?? null, $input['ssh_tunnel_identity'] ?? null,
            );
        } catch (SshTargetConnectionException) {
            throw new TargetConnectorFailure(
                __('The selected reverse route is not in the NL operator approval list for this exact Target, port and tunnel identity.'),
                'ssh_reverse_port', 'reverse_route_not_approved',
            );
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
            $route,
        ): bool {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            $config = SshTargetConfig::query()->where('target_record_id', $locked->getKey())->lockForUpdate()->firstOrFail();
            // Managed route authorization is an independent security binding,
            // not merely editable form fields. Switching it to Direct or
            // swapping Target login credentials while the control key is live
            // would orphan the authorized SSHD listener/key or silently
            // invalidate a managed install. Require explicit Owner revocation
            // before using the existing audited credential rotation path.
            if (SshManagedReverseEnrollment::query()
                ->where('target_record_id', $locked->getKey())
                ->where('state', '!=', 'revoked')->exists()) {
                throw new TargetConnectorFailure(
                    __('Revoke the managed Reverse SSH enrollment before editing the SSH endpoint, trust, route or login credentials.'),
                    'configuration', 'managed_reverse_reconfiguration_requires_revocation',
                );
            }
            if ($route !== null && $locked->getAttribute('relay_record_id') !== null) {
                throw new TargetConnectorFailure(
                    __('A shared Connection Relay and an existing Reverse SSH route cannot be active together. Unbind the Relay first.'),
                    'ssh_route_mode', 'relay_reverse_conflict',
                );
            }
            if ($route !== null) {
                try {
                    $this->reverseRoutes->assertPortAvailable($route, (string) $locked->getKey());
                } catch (SshTargetConnectionException) {
                    throw new TargetConnectorFailure(
                        __('The approved NL reverse listener is already enrolled for another Target. Assign a distinct loopback port and operator identity.'),
                        'ssh_reverse_port', 'reverse_listener_conflict',
                    );
                }
            }
            $credential = $this->credential($locked, lock: true);
            if ($locked->connector_type !== 'ssh_direct'
                || ! hash_equals(
                    (string) $input['configuration_revision'],
                    TargetConfigurationRevision::make($locked, $config->getAttributes(), $credential),
                )) {
                throw new TargetConnectorFailure(__('The SSH Target changed since this form was opened. Reload and review the current settings.'), 'configuration_revision');
            }

            $bindingChanged = $endpoint->host !== $config->host
                || $endpoint->port !== $config->port
                || $endpoint->username !== $config->username
                || $pin->canonicalLine() !== $config->pinned_host_key
                || $method !== $config->auth_method
                || ($route === null ? 'direct' : 'reverse') !== ($config->route_mode ?? 'direct')
                || $route?->listenerPort !== $config->reverse_listener_port
                || $route?->tunnelIdentity !== $config->reverse_tunnel_identity;
            $currentBindingRevision = (int) ($config->binding_revision ?? 0);
            if ($bindingChanged && $currentBindingRevision >= 4294967295) {
                throw new TargetConnectorFailure(
                    __('The SSH binding revision is exhausted; do not reuse an older route or historical Job identity.'),
                    'configuration_revision',
                );
            }
            $nextBindingRevision = $currentBindingRevision + ($bindingChanged ? 1 : 0);

            $replacement = $method === 'password' ? $password : $key;
            if (! $bindingChanged && $replacement === null && $credential instanceof TargetCredential) {
                return false;
            }
            if ($method !== $config->auth_method && $replacement === null) {
                throw new TargetConnectorFailure(__('Changing the login method requires the new password or private key.'), 'ssh_auth_method');
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
                'route_mode' => $route === null ? 'direct' : 'reverse',
                'reverse_listener_port' => $route?->listenerPort,
                'reverse_tunnel_identity' => $route?->tunnelIdentity,
                'binding_revision' => $nextBindingRevision,
            ]);
            try {
                $encrypted = $this->vault->seal($locked, $next, $secret, $newPassphrase);
            } catch (RuntimeException) {
                throw new TargetConnectorFailure(__('The new SSH credential is invalid.'), 'ssh_private_key');
            }

            if ($credential instanceof TargetCredential) {
                $credential->forceFill(['encrypted_payload' => $encrypted])->save();
            } else {
                TargetCredential::query()->create([
                    'target_record_id' => $locked->getKey(),
                    'connector_type' => 'ssh_direct',
                    'purpose' => SshTargetVault::PURPOSE,
                    'encrypted_payload' => $encrypted,
                ]);
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
                'route_mode' => $route === null ? 'direct' : 'reverse',
                'reverse_listener_port' => $route?->listenerPort,
                'reverse_tunnel_identity' => $route?->tunnelIdentity,
                'binding_revision' => $nextBindingRevision,
                'verification_attempt_id' => null,
                'observed_peer_ip' => null,
                'observed_at' => null,
                'updated_at' => now(),
            ]);
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Disconnected,
                'last_error_code' => null,
                'last_tested_at' => null,
                'connected_at' => null,
                'last_success_at' => null,
                'last_failure_at' => null,
                'last_failure_code' => null,
            ])->save();
            $this->activity->recordRequired(
                CorrelationId::current(), 'ssh-target-reconfigure', 'success', $locked,
            );

            return true;
        });
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
