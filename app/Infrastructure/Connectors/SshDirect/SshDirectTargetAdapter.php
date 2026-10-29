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
            'ssh_host' => ['required', 'string', 'max:253'],
            'ssh_port' => ['required', 'integer', 'min:1', 'max:65535'],
            'ssh_username' => ['required', 'string', 'max:128'],
            'ssh_host_key' => ['required', 'string', 'max:4096'],
            'ssh_auth_method' => ['required', Rule::in(['password', 'private_key'])],
            'ssh_password' => ['required_if:ssh_auth_method,password', 'nullable', 'string', 'max:4096'],
            'ssh_private_key' => ['required_if:ssh_auth_method,private_key', 'nullable', 'string', 'max:16384'],
            'ssh_passphrase' => ['nullable', 'string', 'max:4096'],
            'ssh_trust_confirmed' => ['required', 'in:yes'],
        ];
    }

    public function safeOldInputFields(): array
    {
        // ssh_host_key is the server's PUBLIC pin; no login secrets are flashed.
        return [
            'ssh_host', 'ssh_port', 'ssh_username', 'ssh_host_key',
            'ssh_auth_method', 'ssh_trust_confirmed',
        ];
    }

    public function preflightRules(): array
    {
        return [
            'ssh_host' => ['required', 'string', 'max:253'],
            'ssh_port' => ['required', 'integer', 'min:1', 'max:65535'],
        ];
    }

    public function preflight(array $input): TargetPreflightResult
    {
        try {
            return $this->container->make(TargetEndpointPreflight::class)->publicSshTcpEndpoint(
                (string) $input['ssh_host'],
                (int) $input['ssh_port'],
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
        } catch (SshTargetConnectionException $exception) {
            $context = [
                'failure_origin' => 'gateway_admission',
                'failure_stage' => $exception->reason === 'transfer_timed_out' ? 'dns_timeout' : 'dns_lookup',
                'pre_dispatch' => true,
            ];

            throw new TargetConnectorFailure(
                OperationDiagnostics::summary('network_failure', $context),
                'ssh_host', 'network_failure', $context,
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
        try {
            $method = (string) $input['ssh_auth_method'];

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
            );
        } catch (InvalidArgumentException|RuntimeException) {
            throw new TargetConnectorFailure(
                __('SSH registration could not be validated. Check the endpoint, trusted host key, authentication material and unique Target ID.'),
                'ssh_host',
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
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason);
        }
    }

    public function reconnect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->test($target);

            return new TargetConnectorResult(statusMessage: __('SSH recheck verified the pinned host key and login.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason);
        }
    }

    public function disconnect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->disconnect($target);

            return new TargetConnectorResult(statusMessage: __('SSH credential deleted from this Gateway. This does NOT revoke the remote Unix account or terminate external sessions.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason);
        }
    }

    public function test(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(SshTargetConnectionService::class)->test($target);

            return new TargetConnectorResult(statusMessage: __('SSH TCP peer, pinned host key and login verified.'));
        } catch (SshTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->failureMessage($exception), null, $exception->reason);
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
            'egress_denied' => __('The registered SSH destination is not permitted by the TCP/DNS policy.'),
            'tcp_peer_mismatch', 'host_key_mismatch', 'ssh_handshake_failed' => __('SSH server identity could not be verified. No credentials were sent after a host-key mismatch.'),
            'authentication_failed' => __('SSH authentication failed after server identity verification.'),
            'tcp_unreachable' => __('The approved numeric SSH endpoint could not be reached.'),
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
