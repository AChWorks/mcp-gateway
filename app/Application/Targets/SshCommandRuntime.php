<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshCommandAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use phpseclib4\Net\SSH2;
use RuntimeException;
use Throwable;

/** One non-interactive exec on a pinned, Target-bound SSH session, never retried. */
final readonly class SshCommandRuntime
{
    private const STDOUT_LIMIT = 16384;

    private const STDERR_LIMIT = 8192;

    public function __construct(
        private SshTargetVault $vault,
        private SshVerifiedTransport $transport,
        private SshCommandAdmission $admission,
        private AccessControl $access,
    ) {}

    /** @return array<string,mixed> */
    public function run(User $user, Target $target, string $command, int $timeoutSeconds = 10): array
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        // No shell filtering: OS account and its sudo policy control command authority.
        if ($command === '' || trim($command) === '' || strlen($command) > 8192
            || str_contains($command, "\0") || $timeoutSeconds < 1 || $timeoutSeconds > 15) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $this->admission->run((string) $target->getKey(), function () use ($user, $target, $command, $timeoutSeconds): array {
            $fresh = Target::query()->whereKey($target->getKey())->first();
            $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
            $credential = TargetCredential::query()
                ->where('target_record_id', $target->getKey())
                ->where('connector_type', 'ssh_direct')
                ->where('purpose', SshTargetVault::PURPOSE)->first();
            if (! $fresh instanceof Target || $fresh->connector_type !== 'ssh_direct'
                || ! hash_equals((string) $target->target_id, (string) $fresh->target_id)
                || ! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
                throw new SshTargetConnectionException('credential_unavailable');
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
                    $user, $target, $config, $credential, $command, $timeoutSeconds, $started,
                ): array {
                    // Credential disconnect or permission revocation during KEX/login
                    // must not authorize a NEW exec after the revocation.
                    $currentTarget = Target::query()->whereKey($target->getKey())->first();
                    $currentUser = User::query()->whereKey($user->getKey())->first();
                    $currentCredential = TargetCredential::query()->whereKey($credential->getKey())->first();
                    $currentConfig = SshTargetConfig::query()->whereKey($config->getKey())->first();
                    if (! $currentTarget instanceof Target || $currentTarget->connector_type !== 'ssh_direct'
                        || ! hash_equals((string) $target->target_id, (string) $currentTarget->target_id)
                        || ! $currentUser instanceof User
                        || ! $currentCredential instanceof TargetCredential
                        || ! $currentConfig instanceof SshTargetConfig
                        || ! hash_equals((string) $credential->encrypted_payload, (string) $currentCredential->encrypted_payload)
                        || ! hash_equals((string) $config->pinned_host_key, (string) $currentConfig->pinned_host_key)
                        || ! $this->access->allows($currentUser, GatewayPermission::SshCommandRun, $currentTarget)) {
                        throw new SshTargetConnectionException('target_changed');
                    }

                    return $this->executeOnce($ssh, $command, $timeoutSeconds, $peerIp, $config, $started);
                },
            );
        });
    }

    /** @return array<string,mixed> */
    private function executeOnce(
        SSH2 $ssh, string $command, int $timeoutSeconds,
        string $peerIp, SshTargetConfig $config, float $started,
    ): array {
        $stdout = '';
        $stderr = '';
        $stderrObserved = 0;
        $outputExceeded = false;
        $unknown = false;

        // phpseclib delivers stdout and stderr chunks to the callback when
        // quiet mode is off. Only stderr increments its internal stderr log.
        // Exit as soon as either byte budget is exceeded; never buffer floods.
        $ssh->disableQuietMode();
        $ssh->setTimeout($timeoutSeconds);
        try {
            $ssh->exec($command, static function (string $chunk) use (
                $ssh, &$stdout, &$stderr, &$stderrObserved, &$outputExceeded,
            ): bool {
                $seen = strlen($ssh->getStdError());
                $isStderr = $seen > $stderrObserved;
                $stderrObserved = $seen;
                $limit = $isStderr ? self::STDERR_LIMIT : self::STDOUT_LIMIT;
                $current = $isStderr ? strlen($stderr) : strlen($stdout);
                if ($current + strlen($chunk) > $limit) {
                    $remaining = max(0, $limit - $current);
                    if ($isStderr) {
                        $stderr .= substr($chunk, 0, $remaining);
                    } else {
                        $stdout .= substr($chunk, 0, $remaining);
                    }
                    $outputExceeded = true;
                    // Closing an active channel cannot prove the remote command
                    // stopped. Never call it completed and never re-execute.
                    throw new RuntimeException('ssh_output_budget_reached');
                }
                if ($isStderr) {
                    $stderr .= $chunk;
                } else {
                    $stdout .= $chunk;
                }

                return false;
            });
            $unknown = $ssh->isTimeout();
        } catch (Throwable) {
            // After exec() is attempted, dispatch may have succeeded even if
            // the channel, network or local consumer subsequently failed.
            $unknown = true;
        }

        $stdoutEncoded = $this->encoded($stdout);
        $stderrEncoded = $this->encoded($stderr);
        $status = $unknown ? 'outcome_unknown' : 'completed';

        return [
            'status' => $status,
            'connected_ip' => $peerIp,
            'registered_host' => $config->host,
            'username' => $config->username,
            'port' => $config->port,
            'stdout' => $stdoutEncoded['data'],
            'stdout_encoding' => $stdoutEncoded['encoding'],
            'stdout_bytes' => strlen($stdout),
            'stderr' => $stderrEncoded['data'],
            'stderr_encoding' => $stderrEncoded['encoding'],
            'stderr_bytes' => strlen($stderr),
            'exit_code' => $unknown ? null : $ssh->getExitStatus(),
            'complete' => ! $unknown,
            'truncated' => $outputExceeded,
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
