<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorResult;
use App\Application\Targets\TargetEndpointPreflight;
use App\Application\Targets\TargetEnrollmentPreflight;
use App\Application\Targets\TargetPreflightResult;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use App\Support\OperationDiagnostics;
use Illuminate\Contracts\Container\Container;
use Illuminate\Validation\Rule;
use InvalidArgumentException;
use RuntimeException;

/** SSH-specific enrollment, trust and verification never become generic OAuth behavior. */
final readonly class SshDirectTargetAdapter implements TargetConnectorAdapter, TargetEnrollmentPreflight
{
    public function __construct(private Container $container) {}

    public function type(): string
    {
        return 'ssh_direct';
    }

    public function registrationRules(): array
    {
        return [
            'connection_relay_id' => ['nullable', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
            'ssh_host' => ['required', 'string', 'max:253'],
            'ssh_port' => ['required', 'integer', 'min:1', 'max:65535'],
            'ssh_username' => ['required', 'string', 'max:128'],
            'ssh_host_key' => ['required', 'string', 'max:4096'],
            'ssh_auth_method' => ['required', Rule::in(['password', 'private_key'])],
            'ssh_password' => ['required_if:ssh_auth_method,password', 'nullable', 'string', 'max:4096'],
            'ssh_private_key' => ['required_if:ssh_auth_method,private_key', 'nullable', 'string', 'max:16384'],
            'ssh_passphrase' => ['nullable', 'string', 'max:4096'],
            'ssh_trust_confirmed' => ['required', 'in:yes'],
            'ssh_route_mode' => ['nullable', Rule::in(['direct', 'reverse'])],
            'ssh_reverse_port' => ['required_if:ssh_route_mode,reverse', 'nullable', 'integer', 'min:1024', 'max:65535'],
            'ssh_tunnel_identity' => ['required_if:ssh_route_mode,reverse', 'nullable', 'string', 'max:80',
                'regex:/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/D'],
        ];
    }

    public function safeOldInputFields(): array
    {
        // ssh_host_key is the server's PUBLIC pin; no login secrets are flashed.
        return [
            'ssh_host', 'ssh_port', 'ssh_username', 'ssh_host_key',
            'ssh_auth_method', 'ssh_trust_confirmed', 'ssh_route_mode',
            'ssh_reverse_port', 'ssh_tunnel_identity',
        ];
    }

    public function preflightRules(): array
    {
        return [
            'connection_relay_id' => ['nullable', 'string', 'max:64', 'regex:/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D'],
            'ssh_host' => ['required', 'string', 'max:253'],
            'ssh_port' => ['required', 'integer', 'min:1', 'max:65535'],
            'target_id' => ['nullable', 'string', 'max:64'],
            'ssh_route_mode' => ['nullable', Rule::in(['direct', 'reverse'])],
            'ssh_reverse_port' => ['nullable', 'integer', 'min:1024', 'max:65535'],
            'ssh_tunnel_identity' => ['nullable', 'string', 'max:80'],
        ];
    }

    public function preflight(array $input): TargetPreflightResult
    {
        try {
            if (($input['ssh_route_mode'] ?? 'direct') === 'reverse') {
                // Check static NL approval only; a preflight must not open
                // tunnel sockets or imply successful remote authentication.
                $route = $this->container->make(SshReverseRoutePolicy::class)->approve(
                    (string) ($input['target_id'] ?? ''), 'reverse',
                    $input['ssh_reverse_port'] ?? null, $input['ssh_tunnel_identity'] ?? null,
                );
                $endpoint = SshRegisteredEndpoint::fromInput(
                    (string) $input['ssh_host'], (int) $input['ssh_port'], 'preflight',
                );

                return new TargetPreflightResult(
                    __('The reverse route matches the operator-managed approval for this Target. Listener availability and remote SSH identity have NOT been tested.'),
                    __('Only the allowlist was checked; confirm the restricted OpenSSH forward independently, then verify the remote host key and login using Target Details.'),
                    $endpoint->host.':'.$endpoint->port.' via Gateway 127.0.0.1:'.$route->listenerPort,
                    [
                        'ssh_host' => (string) $input['ssh_host'],
                        'ssh_port' => (string) $input['ssh_port'],
                        'ssh_route_mode' => 'reverse',
                        'ssh_reverse_port' => (string) $route->listenerPort,
                        'ssh_tunnel_identity' => $route->tunnelIdentity,
                    ],
                );
            }

            return $this->container->make(TargetEndpointPreflight::class)->publicSshTcpEndpoint(
                (string) $input['ssh_host'],
                (int) $input['ssh_port'],
            );
        } catch (SshTargetConnectionException $exception) {
            if ($exception->reason === 'reverse_route_not_approved') {
                throw new TargetConnectorFailure(
                    __('No matching Gateway operator approval exists for this reverse route and Target.'),
                    'ssh_reverse_port', 'reverse_route_not_approved',
                );
            }
            $context = [
                'failure_origin' => 'gateway_admission',
                'failure_stage' => $exception->reason === 'transfer_timed_out' ? 'dns_timeout' : 'dns_lookup',
                'pre_dispatch' => true,
            ];
            throw new TargetConnectorFailure(
                OperationDiagnostics::summary('network_failure', $context),
                'ssh_host', 'network_failure', $context,
            );
        } catch (UnsafeOutboundTarget $exception) {
            throw new TargetConnectorFailure(
                OperationDiagnostics::summary('egress_denied', $exception->diagnostics()),
                'ssh_host', 'egress_denied', $exception->diagnostics(),
            );
        } catch (InvalidArgumentException $exception) {
            throw new TargetConnectorFailure(
                __('The SSH host or port is invalid. Enter a canonical public hostname or IP address and a valid TCP port.'),
                'ssh_host', 'invalid_input',
            );
        } catch (RuntimeException $exception) {
            $context = [
                'failure_origin' => 'gateway_admission',
                'failure_stage' => 'dns_lookup',
                'pre_dispatch' => true,
                'gateway_error_message' => $exception->getMessage(),
            ];

            throw new TargetConnectorFailure(
                OperationDiagnostics::summary('network_failure', $context),
                'ssh_host', 'network_failure', $context,
            );
        }
    }

    public function register(array $input): Target
    {
        $method = (string) $input['ssh_auth_method'];

        try {
            return $this->container->make(SshTargetRegistration::class)->register(
                (string) $input['target_id'],
                (string) $input['display_name'],
                (string) $input['ssh_host'],
                (int) $input['ssh_port'],
                (string) $input['ssh_username'],
                (string) $input['ssh_host_key'],
                $method,
                (string) ($input[$method === 'password' ? 'ssh_password' : 'ssh_private_key'] ?? ''),
                $method === 'private_key' ? ($input['ssh_passphrase'] ?? null) : null,
                $input['ai_guidance'] ?? null,
                (string) ($input['ssh_route_mode'] ?? 'direct'),
                isset($input['ssh_reverse_port']) ? (int) $input['ssh_reverse_port'] : null,
                $input['ssh_tunnel_identity'] ?? null,
                $input['connection_relay_id'] ?? null,
            );
        } catch (ConnectionRelayUnavailable) {
            throw new TargetConnectorFailure(__('The selected Connection Relay is disabled or lacks verified host isolation. Configure it in System first.'), 'connection_relay_id', 'relay_unavailable');
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure(
                $exception->reason === 'relay_reverse_conflict'
                    ? __('A shared Connection Relay cannot be combined with existing Reverse SSH.')
                    : ($exception->reason === 'reverse_listener_conflict'
                    ? __('The approved local listener port is already enrolled for another SSH Target. Use a different operator-assigned port.')
                    : __('Reverse SSH requires an exact, independent Gateway operator approval for the Target, listener port and tunnel identity.')),
                $exception->reason === 'relay_reverse_conflict' ? 'connection_relay_id' : 'ssh_reverse_port', $exception->reason,
            );
        } catch (InvalidArgumentException $exception) {
            // All of these originate from our deterministic enrollment validators,
            // not from the remote SSH service. Retain their typed, safe provenance.
            $cause = $exception->getMessage();
            [$code, $field, $message] = match (true) {
                str_contains($cause, 'already registered') => [
                    'duplicate_target_id', 'target_id',
                    __('That Target ID already exists. Choose a different stable Target ID.'),
                ],
                str_contains($cause, 'host key'), str_contains($cause, 'public-key'),
                str_contains($cause, 'trusted SSH server') => [
                    'invalid_ssh_host_key', 'ssh_host_key',
                    __('The trusted SSH server public key is malformed or has an unsupported algorithm. Paste one independently verified OpenSSH host public key.'),
                ],
                str_contains($cause, 'username') => [
                    'invalid_ssh_username', 'ssh_username', __('Enter a valid Unix SSH login username.'),
                ],
                str_contains($cause, 'port') => [
                    'invalid_ssh_port', 'ssh_port', __('Enter a valid SSH TCP port (1–65535).'),
                ],
                str_contains($cause, 'host') => [
                    'invalid_ssh_host', 'ssh_host', __('Enter a canonical SSH hostname or IP address.'),
                ],
                default => [
                    'invalid_input', 'target_id', __('Check the Target ID and required registration fields.'),
                ],
            };
            throw new TargetConnectorFailure($message, $field, $code, [
                'failure_origin' => 'gateway_admission',
                'pre_dispatch' => true, // Registration never opens an SSH connection.
                'source_error_code' => $code,
                'source_error_message' => $cause,
                'exception_class' => $exception::class,
            ]);
        } catch (RuntimeException $exception) {
            $credential = $exception->getMessage() === 'SSH authentication material is invalid.';
            $code = $credential ? 'registration_credential_invalid' : 'registration_storage_failed';

            throw new TargetConnectorFailure(
                $credential
                    ? __('SSH login credential material is invalid. Enter the password or private key again.')
                    : __('Gateway could not safely store the new SSH Target. Check the diagnostic reference and Gateway storage/encryption configuration before retrying.'),
                $credential ? ($method === 'password' ? 'ssh_password' : 'ssh_private_key') : 'target_id',
                $code,
                [
                    'failure_origin' => 'gateway_admission',
                    'pre_dispatch' => true, // Credential/storage validation is local.
                    'source_error_code' => $code,
                    // SQL/vault exceptions may contain parameter values: do not
                    // echo their text into logs or any browser-visible session.
                    'exception_class' => $exception::class,
                ],
            );
        }
    }

    public function registrationStatus(): string
    {
        return __('SSH Target registered with encrypted credentials and an out-of-band host-key pin. Authentication has NOT yet been verified.');
    }

    public function configurationRules(Target $target): array
    {
        return [
            'configuration_revision' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]{64}$/D'],
            'ssh_host' => ['required', 'string', 'max:253'],
            'ssh_port' => ['required', 'integer', 'min:1', 'max:65535'],
            'ssh_username' => ['required', 'string', 'max:128'],
            'ssh_host_key' => ['required', 'string', 'max:4096'],
            'ssh_trust_confirmed' => ['required', 'in:yes'],
            'ssh_auth_method' => ['required', Rule::in(['password', 'private_key'])],
            // Blank login fields preserve the encrypted secret when the
            // method remains unchanged; changing methods requires new input.
            'ssh_password' => ['nullable', 'string', 'max:4096'],
            'ssh_private_key' => ['nullable', 'string', 'max:16384'],
            'ssh_passphrase' => ['nullable', 'string', 'max:4096'],
            'ssh_route_mode' => ['nullable', Rule::in(['direct', 'reverse'])],
            'ssh_reverse_port' => ['required_if:ssh_route_mode,reverse', 'nullable', 'integer', 'min:1024', 'max:65535'],
            'ssh_tunnel_identity' => ['required_if:ssh_route_mode,reverse', 'nullable', 'string', 'max:80',
                'regex:/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/D'],
        ];
    }

    public function configurationRevision(Target $target): string
    {
        return $this->container->make(SshTargetReconfiguration::class)->revision($target);
    }

    public function updateConfiguration(Target $target, array $input): TargetConnectorResult
    {
        $changed = $this->container->make(SshTargetReconfiguration::class)->update($target, $input);

        return new TargetConnectorResult(statusMessage: $changed
            ? __('SSH settings saved with encrypted credentials. Previous verification cleared; verify the new endpoint, pinned key and login before using this Target.')
            : __('No SSH configuration change was necessary.'));
    }

    public function connect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->test($target);

            return new TargetConnectorResult(statusMessage: __('SSH host key, numeric TCP peer and login verified. No command was run.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function reconnect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->test($target);

            return new TargetConnectorResult(statusMessage: __('SSH recheck verified the pinned host key and login.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function disconnect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->disconnect($target);

            return new TargetConnectorResult(statusMessage: __('SSH credential deleted from this Gateway. This does NOT revoke the remote Unix account or terminate external sessions.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function test(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->test($target);

            return new TargetConnectorResult(statusMessage: __('SSH TCP peer, pinned host key and login verified.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function adminDetails(Target $target): array
    {
        $id = $target->getKey();
        $config = SshTargetConfig::query()->where('target_record_id', $id)->first();

        return [
            'sshConfig' => $config,
            'sshFingerprint' => $config instanceof SshTargetConfig
                ? SshHostKeyPin::fromLine($config->pinned_host_key)->fingerprint()
                : null,
            'sshHasCredential' => TargetCredential::query()
                ->where('target_record_id', $id)->where('connector_type', $this->type())
                ->where('purpose', SshTargetVault::PURPOSE)->exists(),
        ];
    }

    public function publicMetadata(Target $target): array
    {
        return ['ssh' => SshTargetIdentity::safeMetadata($target)];
    }

    public function hasPendingDeletion(Target $target): bool
    {
        // SSH has no OAuth callbacks/intents. Shared credential/state checks still apply.
        return false;
    }

    private function failureMessage(SshTargetConnectionException $exception): string
    {
        return match ($exception->reason) {
            'egress_denied' => isset($exception->diagnostics['outbound_rejection_reason'])
                ? OperationDiagnostics::summary('egress_denied', $exception->diagnostics)
                : __('The registered SSH destination is not permitted by the TCP/DNS policy.'),
            'tcp_peer_mismatch', 'host_key_mismatch', 'ssh_handshake_failed' => __('SSH server identity could not be verified. No credentials were sent after a host-key mismatch.'),
            'authentication_failed' => __('SSH authentication failed after server identity verification.'),
            'tcp_unreachable' => __('The approved numeric SSH endpoint could not be reached.'),
            'reverse_route_not_approved' => __('The operator-approved reverse listener does not match this Target configuration. No connection was attempted.'),
            'reverse_listener_unavailable' => __('The approved local reverse SSH listener is unavailable on NL. Verify the forward and systemd status on the initiating host; no direct fallback is attempted.'),
            'credential_invalid', 'credential_unavailable' => __('The stored SSH credential is unavailable or invalid.'),
            'connection_busy' => __('Another SSH verification is already in progress for this Target.'),
            'rate_limited' => __('Too many SSH verification attempts were made for this Target. Try again later.'),
            'admission_unavailable' => __('SSH verification is temporarily unavailable because its safety guard could not be acquired.'),
            'target_changed' => __('The SSH Target changed while verification was in progress. Retry after reviewing it.'),
            'verification_superseded' => __('A newer SSH verification has superseded this result. Reload the Target status.'),
            default => __('The SSH connection could not be verified safely.'),
        };
    }
}
