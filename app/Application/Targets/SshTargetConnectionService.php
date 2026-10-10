<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshConnectionAdmission;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Support\CorrelationId;
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
    ) {}

    /** Authenticates a single pinned connection without running any command. */
    public function test(Target $target): string
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
                $target, $config, $credential, &$attemptId,
            ): string {
                $attemptId = $this->verification->begin($target, $config, $credential);
                $material = $this->vault->open($target, $config, $credential);

                return $this->transport->authenticate(
                    $config->endpoint(), SshHostKeyPin::fromLine($config->pinned_host_key),
                    $config->auth_method, $material['secret'], $material['passphrase'],
                );
            });
        } catch (SshTargetConnectionException $exception) {
            if ($attemptId !== null && ! in_array($exception->reason, [
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

        // Short state transaction after network I/O; it checks the attempt
        // fence under the same Target row lock used to issue new fences.
        $this->verification->succeeded($target, $config, $credential, $attemptId, $ip);

        return $ip;
    }

    /** Local credential deletion; it does not revoke a remote Unix login. */
    public function disconnect(Target $target): void
    {
        if ($target->connector_type !== 'ssh_direct') {
            throw new SshTargetConnectionException('unsupported_connector');
        }
        DB::transaction(function () use ($target): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            TargetCredential::query()->where('target_record_id', $locked->getKey())
                ->where('connector_type', 'ssh_direct')->delete();
            SshTargetConfig::query()->where('target_record_id', $locked->getKey())
                ->update(['verification_attempt_id' => null, 'observed_peer_ip' => null, 'observed_at' => null]);
            $locked->forceFill([
                'connection_state' => TargetConnectionState::Disconnected,
                'last_error_code' => null,
                'connected_at' => null,
            ])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-credential-disconnect', 'success', $locked);
        });
    }

}
