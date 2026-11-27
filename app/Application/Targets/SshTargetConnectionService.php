<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshConnectionAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Support\CorrelationId;
use Closure;
use Illuminate\Support\Facades\DB;
use Throwable;

final readonly class SshTargetConnectionService
{
    public function __construct(
        private SshTargetVault $vault,
        private SshVerifiedTransport $transport,
        private SshConnectionAdmission $admission,
        private SshVerificationState $verification,
        private ActivityRecorder $activity,
        private SshReverseRoutePolicy $reverseRoutes,
        private ConnectionRelayRoutes $relayRoutes,
    ) {}

    /** Authenticates a single pinned connection without running any command. */
    public function test(Target $target, ?Closure $authorize = null): string
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->first();
        $credential = TargetCredential::query()
            ->where('target_record_id', $target->getKey())
            ->where('connector_type', 'ssh_direct')
            ->where('purpose', SshTargetVault::PURPOSE)->first();
        if (! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
            throw new SshTargetConnectionException('credential_unavailable');
        }

        // A persisted attempt fence is claimed while admission is held, before
        // dialing. Even if its finite lease expires, stale completion cannot
        // overwrite the result of a newer admitted attempt.
        $attemptId = null;
        try {
            $ip = $this->admission->run((string) $target->getKey(), function () use (
                $target, $config, $credential, &$attemptId, $authorize,
            ): string {
                $attemptId = $this->verification->begin($target, $config, $credential);
                $material = $this->vault->open($target, $config, $credential);
                $route = $this->reverseRoutes->forTarget($target);
                $relay = $this->relayRoutes->sshRouteForTarget($target);

                return $this->transport->authenticate(
                    $config->endpoint(), SshHostKeyPin::fromLine($config->pinned_host_key),
                    $config->auth_method, $material['secret'], $material['passphrase'], $route, $relay,
                    function () use ($target, $config, $credential, $attemptId, $authorize): void {
                        if ($authorize !== null && ! $authorize()) {
                            throw new SshTargetConnectionException('forbidden');
                        }
                        $this->verification->assertCurrentAttempt($target, $config, $credential, $attemptId);
                        $this->reverseRoutes->forTarget($target);
                        $this->relayRoutes->sshRouteForTarget($target);
                    },
                );
            });
        } catch (SshTargetConnectionException $exception) {
            if ($attemptId !== null && $exception->reason === 'forbidden') {
                $this->verification->abandon($target, $config, $credential, $attemptId);
            } elseif ($attemptId !== null && ! in_array($exception->reason, [
                'connection_busy', 'rate_limited', 'admission_unavailable',
            ], true)) {
                $this->verification->failed($target, $config, $credential, $attemptId, $exception->reason);
            }
            throw $exception;
        } catch (Throwable) {
            if ($attemptId !== null) {
                $this->verification->failed($target, $config, $credential, $attemptId, 'credential_unavailable');
            }
            throw new SshTargetConnectionException('credential_unavailable');
        }

        if (! is_string($attemptId)) {
            throw new SshTargetConnectionException('verification_superseded');
        }

        // Do not report a successful login over a listener revoked during
        // KEX/login. The end-host pin alone does not grant route ownership.
        try {
            $this->reverseRoutes->forTarget($target);
            $this->relayRoutes->sshRouteForTarget($target);
        } catch (SshTargetConnectionException $exception) {
            $this->verification->failed($target, $config, $credential, $attemptId, $exception->reason);

            throw $exception;
        }

        // Short state transaction after network I/O; it checks the attempt
        // fence under the same Target row lock used to issue new fences.
        $this->verification->succeeded($target, $config, $credential, $attemptId, $ip);

        return $ip;
    }

    /** Local credential deletion; it does not revoke a remote Unix login. */
    public function disconnect(Target $target, ?Closure $authorize = null): void
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        DB::transaction(function () use ($target, $authorize): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            if ($authorize !== null && ! $authorize()) {
                throw new SshTargetConnectionException('forbidden');
            }
            TargetCredential::query()->where('target_record_id', $locked->getKey())
                ->where('connector_type', 'ssh_direct')->delete();
            // A pending bootstrap must not re-install a retired login key.
            SshManagedReverseEnrollment::query()->where('target_record_id', $locked->getKey())
                ->where('login_public_key', '!=', '')->update(['login_public_key' => '']);

            SshTargetConfig::query()->where('target_record_id', $locked->getKey())
                ->update(['verification_attempt_id' => null, 'observed_peer_ip' => null, 'observed_at' => null]);
            TargetCheckEvidence::invalidateLocked($locked, TargetCheckEvidence::SSH_LOGIN);
            $locked->forceFill([
                'last_tested_at' => null,
                'connection_state' => TargetConnectionState::Disconnected,
                'last_error_code' => null,
                'connected_at' => null,
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-credential-disconnect', 'success', $locked);
        });
    }
}
