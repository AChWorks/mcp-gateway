<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Application\Mcp\McpDispatchAdmission;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshCommandAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use phpseclib4\Net\SSH2;
use Throwable;

/** One non-interactive exec on a pinned, Target-bound SSH session, never retried. */
final readonly class SshCommandRuntime
{
    public function __construct(
        private SshTargetVault $vault,
        private SshVerifiedTransport $transport,
        private SshCommandAdmission $admission,
        private AccessControl $access,
        private OperationalSettings $settings,
        private McpDispatchAdmission $dispatchAdmission,
    ) {}

    /** @return array<string,mixed> */
    public function run(
        User $user, Target $target, string $command, int $timeoutSeconds = 10,
        ?string $expectedTargetBinding = null,
    ): array {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        // No shell filtering: OS account and its sudo policy control command authority.
        $limits = $this->settings->sshCommandLimits();
        if ($command === '' || trim($command) === '' || strlen($command) > $limits['max_bytes']
            || str_contains($command, "\0") || $timeoutSeconds < 1
            || $timeoutSeconds > $limits['max_seconds']) {
            throw new SshTargetConnectionException('invalid_input');
        }

        // A finite FPM/LSAPI worker that cannot reach the selected timeout
        // must fail before attempting a possibly effectful remote command.
        // An unlimited CLI/worker (0) is allowed; proxy/client hop limits
        // still require separately measured operator qualification.
        $workerSeconds = (int) ini_get('max_execution_time');
        if ($workerSeconds > 0 && $workerSeconds < $timeoutSeconds + 15) {
            throw new SshTargetConnectionException('timeout_unsupported');
        }

        return $this->admission->run((string) $target->getKey(), function () use ($user, $target, $command, $timeoutSeconds, $expectedTargetBinding): array {
            $fresh = Target::query()->whereKey($target->getKey())->first();
            $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
            if ($fresh instanceof Target && $fresh->operations_paused) {
                throw new SshTargetConnectionException('target_paused');
            }
            $credential = TargetCredential::query()
                ->where('target_record_id', $target->getKey())
                ->where('connector_type', 'ssh_direct')
                ->where('purpose', SshTargetVault::PURPOSE)->first();
            if (! $fresh instanceof Target || $fresh->connector_type !== 'ssh_direct'
                || $fresh->getAttribute('connection_state') !== TargetConnectionState::Connected
                || ! hash_equals((string) $target->target_id, (string) $fresh->target_id)
                || ! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
                throw new SshTargetConnectionException('credential_unavailable');
            }
            if ($expectedTargetBinding !== null
                && ! hash_equals($expectedTargetBinding, SshTargetBinding::hash($fresh, $config))) {
                throw new SshTargetConnectionException('target_changed');
            }
            try {
                $material = $this->vault->open($fresh, $config, $credential);
                $pin = SshHostKeyPin::fromLine($config->pinned_host_key);
            } catch (Throwable) {
                throw new SshTargetConnectionException('credential_unavailable');
            }

            $started = microtime(true);

            return $this->transport->withAuthenticatedSession(
                $config->endpoint(), $pin, $config->auth_method,
                $material['secret'], $material['passphrase'],
                function (SSH2 $ssh, string $peerIp) use (
                    $user, $target, $config, $credential, $command, $timeoutSeconds, $started, $expectedTargetBinding,
                ): array {
                    // Credential disconnect or permission revocation during KEX/login
                    // must not authorize a NEW exec after the revocation.
                    $currentTarget = Target::query()->whereKey($target->getKey())->first();
                    $currentUser = User::query()->whereKey($user->getKey())->first();
                    $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
                    $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
                    if ($currentTarget instanceof Target && $currentTarget->operations_paused) {
                        throw new SshTargetConnectionException('target_paused');
                    }
                    if (! $currentTarget instanceof Target || $currentTarget->connector_type !== 'ssh_direct'
                        || $currentTarget->getAttribute('connection_state') !== TargetConnectionState::Connected
                        || ! hash_equals((string) $target->target_id, (string) $currentTarget->target_id)
                        || ! $currentUser instanceof User
                        || ! $currentCredential instanceof TargetCredential
                        || ! $currentConfig instanceof SshTargetConfig
                        || ! hash_equals((string) $credential->encrypted_payload, (string) $currentCredential->encrypted_payload)
                        || ! hash_equals((string) $config->pinned_host_key, (string) $currentConfig->pinned_host_key)
                        || ! hash_equals((string) $config->host, (string) $currentConfig->host)
                        || $config->port !== $currentConfig->port
                        || ! hash_equals((string) $config->username, (string) $currentConfig->username)
                        || ! hash_equals((string) $config->auth_method, (string) $currentConfig->auth_method)
                        || ($expectedTargetBinding !== null
                            && ! hash_equals($expectedTargetBinding, SshTargetBinding::hash($currentTarget, $currentConfig)))
                        || ! $this->access->allows($currentUser, GatewayPermission::SshCommandRun, $currentTarget)
                        || ! $this->dispatchAdmission->allows($currentUser)) {
                        throw new SshTargetConnectionException('target_changed');
                    }

                    return $this->executeOnce($ssh, $command, $timeoutSeconds, $peerIp, $config, $started);
                },
            );
        }, $timeoutSeconds);
    }

    /** @return array<string,mixed> */
    private function executeOnce(
        SSH2 $ssh, string $command, int $timeoutSeconds,
        string $peerIp, SshTargetConfig $config, float $started,
    ): array {
        // The collector must be ready BEFORE we send any remote command.
        // It clears phpseclib's cumulative private stderr log per packet;
        // otherwise verbose stderr would grow without bound *inside* SSH2.
        try {
            $limits = $this->settings->sshCommandOutputLimits();
            $collector = new SshCommandOutputCollector(
                $ssh, $limits['stdout_bytes'], $limits['stderr_bytes'],
            );
        } catch (Throwable) {
            throw new SshTargetConnectionException('ssh_output_collector_unavailable');
        }

        $unknown = false;
        $exit = null;
        $deadline = new SshCommandExecutionDeadline($timeoutSeconds);
        $ssh->disableQuietMode();
        $ssh->setTimeout($deadline->remainingSocketSeconds());
        try {
            $ssh->exec($command, static function (string $chunk) use ($ssh, $collector, $deadline): bool {
                // A busy stream can spend almost no time blocked in socket
                // reads. Check elapsed monotonic time for EVERY delivered
                // packet, independently of phpseclib's curTimeout counter.
                $deadline->remainingSocketSeconds();
                $collector->observe($ssh, $chunk);

                // Clamp the next socket wait too: after a burst of packets,
                // phpseclib must not get a fresh full-length blocking wait.
                // Throwing on expiry unwinds exec directly. Returning true
                // instead would enter close_channel's separate drain loop.
                $ssh->setTimeout($deadline->remainingSocketSeconds());

                // Preserve genuine exit evidence for finite output. Reaching
                // a capture limit does not authorize closing this channel.
                return false;
            });
            $unknown = $deadline->expired() || $ssh->isTimeout();
            $exit = $unknown ? null : $ssh->getExitStatus();
            if ($exit === null) {
                $unknown = true;
            }
        } catch (Throwable) {
            // Once exec() was attempted, the remote command may already be
            // running. Never fabricate exit evidence or silently replay it.
            $unknown = true;
        }

        $capture = $collector->result();
        $stdoutEncoded = $this->encoded($capture['stdout']);
        $stderrEncoded = $this->encoded($capture['stderr']);
        $status = $unknown ? 'outcome_unknown' : 'completed';

        return [
            'status' => $status,
            'connected_ip' => $peerIp,
            'registered_host' => $config->host,
            'username' => $config->username,
            'port' => $config->port,
            'stdout' => $stdoutEncoded['data'],
            'stdout_encoding' => $stdoutEncoded['encoding'],
            'stdout_bytes' => $capture['stdout_bytes'],
            'stdout_total_bytes' => $capture['stdout_total_bytes'],
            'stdout_truncated' => $capture['stdout_truncated'],
            'stderr' => $stderrEncoded['data'],
            'stderr_encoding' => $stderrEncoded['encoding'],
            'stderr_bytes' => $capture['stderr_bytes'],
            'stderr_total_bytes' => $capture['stderr_total_bytes'],
            'stderr_truncated' => $capture['stderr_truncated'],
            'exit_code' => $unknown ? null : $exit,
            'complete' => ! $unknown,
            'truncated' => $capture['stdout_truncated'] || $capture['stderr_truncated'],
            'continuation_available' => false,
            'duration_ms' => (int) round((microtime(true) - $started) * 1000),
        ];
    }

    /** @return array{data:string,encoding:string} */
    private function encoded(string $bytes): array
    {
        return mb_check_encoding($bytes, 'UTF-8')
            ? ['data' => $bytes, 'encoding' => 'utf-8']
            : ['data' => base64_encode($bytes), 'encoding' => 'base64'];
    }
}
