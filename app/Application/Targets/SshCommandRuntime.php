<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Application\Access\OperationAdmission;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshCommandAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use Closure;
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
        private OperationAdmission $operationAdmission,
        private SshExecutionAdmission $executionAdmission,
        private SshReverseRoutePolicy $reverseRoutes,
        private ConnectionRelayRoutes $relayRoutes,
        private SshFileRuntime $files,
        private SshStagedScriptExecution $scripts,
    ) {}

    /** @return array<string,mixed> */
    public function run(
        User $user, Target $target, string $command, int $timeoutSeconds = 10,
        ?string $expectedTargetBinding = null,
        ?Closure $beforeRemoteEffect = null,
        ?string $expectedCredentialDispatch = null,
        ?Closure $admitRemoteEffect = null,
    ): array {
        return $this->runAdmitted($user, $target, $command, $timeoutSeconds, $expectedTargetBinding,
            $beforeRemoteEffect, $expectedCredentialDispatch, $admitRemoteEffect);
    }

    /** @return array<string,mixed> */
    public function runScript(User $user, Target $target, string $script, string $interpreter, int $timeoutSeconds = 10): array
    {
        if (! SshStagedScriptExecution::validInterpreter($interpreter) || ! mb_check_encoding($script, 'UTF-8')) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->runAdmitted($user, $target, $script, $timeoutSeconds, interpreter: $interpreter);
    }

    /** @return array<string,mixed> */
    private function runAdmitted(
        User $user, Target $target, string $command, int $timeoutSeconds,
        ?string $expectedTargetBinding = null, ?Closure $beforeRemoteEffect = null,
        ?string $expectedCredentialDispatch = null, ?Closure $admitRemoteEffect = null,
        ?string $interpreter = null,
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

        // Unlike native exec's execution-phase budget, staged scripts share
        // one absolute deadline from admission through preparation, upload,
        // execution and best-effort cleanup. No per-stage timeout reset.
        $deadline = $interpreter === null ? null : new SshCommandExecutionDeadline($timeoutSeconds);
        $permissions = $interpreter === null
            ? [GatewayPermission::SshCommandRun]
            : [GatewayPermission::SshCommandRun, GatewayPermission::SshFileWrite];
        $context = $this->operationAdmission->capture($user, $beforeRemoteEffect);
        if (in_array(false, $this->access->allowsTargetPermissions($user, $target, $permissions), true)) {
            throw new SshTargetConnectionException('forbidden');
        }

        return $this->admission->run((string) $target->getKey(), function () use ($context, $user, $target, $command, $timeoutSeconds, $expectedTargetBinding, $expectedCredentialDispatch, $admitRemoteEffect, $interpreter, $deadline, $permissions, $limits): array {
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
            if (($expectedTargetBinding !== null
                && ! hash_equals($expectedTargetBinding, SshTargetBinding::hash($fresh, $config)))
                || ($expectedCredentialDispatch !== null
                    && ! hash_equals($expectedCredentialDispatch, $credential->dispatchFingerprint()))) {
                throw new SshTargetConnectionException('target_changed');
            }
            try {
                $material = $this->vault->open($fresh, $config, $credential);
                $pin = SshHostKeyPin::fromLine($config->pinned_host_key);
            } catch (Throwable) {
                throw new SshTargetConnectionException('credential_unavailable');
            }

            $guard = $this->executionAdmission->guard($context, $user, $fresh, $permissions, $config, $credential);
            $guard();
            $route = $this->reverseRoutes->forTarget($fresh);
            $relay = $this->relayRoutes->sshRouteForTarget($fresh);
            $started = microtime(true);

            $dispatch = static function (string $phase) use ($guard, $admitRemoteEffect): void {
                if ($admitRemoteEffect === null) {
                    $guard();
                } elseif (! $admitRemoteEffect($guard, $phase)) {
                    throw new SshTargetConnectionException('authorization_revoked');
                }
            };

            // Each exec uses a fresh pinned session: the locked SSH2 library
            // retains its last exit_status across exec() calls. Never accept
            // a control command's exit as evidence that the script completed.
            $execute = function (string $text, ?Closure $onAttempt = null) use (
                $config, $pin, $material, $dispatch, $fresh, $timeoutSeconds, $started, $route, $relay, $deadline,
            ): array {
                $deadline?->assertAvailable();

                return $this->transport->withAuthenticatedSession(
                    $config->endpoint(), $pin, $config->auth_method,
                    $material['secret'], $material['passphrase'],
                    function (SSH2 $ssh, string $peerIp) use (
                        $dispatch, $fresh, $config, $text, $timeoutSeconds, $started, $deadline, $onAttempt,
                    ): array {
                        return $this->executeOnce($ssh, $text, $timeoutSeconds, $peerIp, $config, $started,
                            $fresh->transportKind(), $dispatch, $deadline, $onAttempt);
                    },
                    $route, $relay, static fn () => $dispatch('login'), deadlineNs: $deadline?->expiresAtNs(),
                );
            };
            if ($interpreter === null || $deadline === null) {
                return $execute($command);
            }

            $binding = SshTargetBinding::executionFingerprint($fresh, $config, $credential);
            // The verified streaming engine owns its normal SFTP admission,
            // integrity and publication. Compose command + write authority
            // into its native guard; do not acquire the command lock again.
            $upload = function (string $directory, mixed $source, int $bytes, string $sha256, Closure $verifyStaging) use (
                $user, $fresh, $binding, $deadline, $timeoutSeconds, $limits,
            ): array {
                return $this->files->uploadFromStream($user, $fresh, $directory.'/script', $source,
                    $bytes, $sha256, $limits['max_bytes'], $timeoutSeconds, $directory,
                    overallDeadlineNs: $deadline->expiresAtNs(), expectedExecution: $binding,
                    additionalPermissions: [GatewayPermission::SshCommandRun], verifyStaging: $verifyStaging,
                );
            };

            return $this->scripts->run($command, $interpreter, $deadline, $execute, $upload);
        }, $timeoutSeconds);
    }

    /** @return array<string,mixed> */
    private function executeOnce(
        SSH2 $ssh, string $command, int $timeoutSeconds,
        string $peerIp, SshTargetConfig $config, float $started, string $routeMode, Closure $dispatch,
        ?SshCommandExecutionDeadline $deadline = null, ?Closure $onAttempt = null,
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
        $ssh->disableQuietMode();
        $dispatch('command');
        $deadline ??= new SshCommandExecutionDeadline($timeoutSeconds);
        $deadline->assertAvailable();
        $ssh->setTimeout($deadline->remainingSocketSeconds());
        // Only this boundary makes a user-script launch potentially sent.
        // Login, a collector failure or a stale admission cannot do so.
        $deadline->assertAvailable();
        $onAttempt?->__invoke();
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
            'connected_ip' => $routeMode !== 'direct' || $peerIp === '' ? null : $peerIp,
            'route_mode' => $routeMode,
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
