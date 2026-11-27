<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use Closure;
use phpseclib4\Net\SFTP;

/** Fresh route/material for one follow-up, never the old Job's dispatch authority. */
final readonly class SshJobRemoteIdentity
{
    public const MARKER = '.job-identity';

    private function __construct(
        public string $binding,
        public string $credentialDispatch,
        private string $directory,
        private ?string $witness,
    ) {}

    public static function forJob(Target $target, object $row, string $directory): self
    {
        $fresh = Target::query()->find($target->getKey());
        if (! $fresh instanceof Target || $fresh->connector_type !== 'ssh_direct'
            || (string) $fresh->getKey() !== (string) $row->target_record_id) {
            throw new SshTargetConnectionException('target_changed');
        }
        if ($fresh->operations_paused) {
            throw new SshTargetConnectionException('target_paused');
        }
        if ($fresh->getAttribute('connection_state') !== TargetConnectionState::Connected) {
            throw new SshTargetConnectionException('target_unavailable');
        }
        $config = SshTargetConfig::query()->where('target_record_id', $fresh->getKey())->first();
        $credential = TargetCredential::query()->where('target_record_id', $fresh->getKey())
            ->where('connector_type', 'ssh_direct')->where('purpose', SshTargetVault::PURPOSE)->first();
        if (! $config instanceof SshTargetConfig || ! $credential instanceof TargetCredential) {
            throw new SshTargetConnectionException('credential_unavailable');
        }
        $binding = SshTargetBinding::hash($fresh, $config);
        $peer = $row->original_peer_fingerprint ?? null;
        $rebound = ! hash_equals((string) $row->target_binding_hash, $binding);
        if ($peer !== null) {
            if (! hash_equals((string) $peer, self::peerFingerprint($fresh, $config))) {
                throw new SshTargetConnectionException('target_changed');
            }
        } elseif ($rebound) {
            // Retained pre-marker records cannot prove their artifact on a
            // new route. Keep local history; never infer original identity.
            throw new SshTargetConnectionException('job_identity_unverified');
        }

        return new self($binding, $credential->dispatchFingerprint(), $directory,
            $rebound && $peer !== null ? self::witness((string) $row->id, (string) $peer) : null);
    }

    /**
     * Artifact identity is independent of routing and authentication method.
     * Endpoint aliases, ports or fresh credentials are not evidence of a
     * different OS account/host key. A changed execution binding still
     * requires the exact remote private witness under the fresh pin/login.
     */
    public static function peerFingerprint(Target $target, SshTargetConfig $config): string
    {
        return hash('sha256', json_encode([
            (string) $target->getKey(), (string) $target->target_id,
            $config->username, $config->pinned_host_key,
        ], JSON_THROW_ON_ERROR));
    }

    public static function witness(string $id, string $peer): string
    {
        return hash_hmac('sha256', "ssh-job-artifact-v1\0".$id."\0".$peer, (string) config('app.key'));
    }

    /** Verify the exact private artifact in the SAME remote exec as the follow-up. */
    public function command(string $command): string
    {
        if ($this->witness === null) {
            return $command;
        }

        $artifact = new SshPrivateArtifactWitness($this->directory, self::MARKER, $this->witness, 'job_identity_unverified');

        return 'if ! { '.$artifact->shellCheck()
            .'; }; then printf "ssh_job_identity_unverified\n" >&2; exit 1; fi; '.$command;
    }

    /** @return (Closure(SFTP, Closure():void):void)|null */
    public function sftpVerifier(): ?Closure
    {
        if ($this->witness === null) {
            return null;
        }

        return (new SshPrivateArtifactWitness($this->directory, self::MARKER, $this->witness, 'job_identity_unverified'))->sftpVerifier();
    }
}
