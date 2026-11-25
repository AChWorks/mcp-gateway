<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Models\User;
use App\Support\CorrelationId;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use phpseclib4\Crypt\EC;
use RuntimeException;

/**
 * One-use token authorizes only the control key registration for one Target.
 * A successful claim does not verify the remote Target or mark it connected.
 */
final readonly class SshManagedReverseEnrollmentService
{
    private const PORT_START = 42000;

    private const PORT_END = 45000;

    public function __construct(
        private SshTargetVault $vault,
        private ActivityRecorder $activity,
        private SshManagedReverseAuthorizedKeys $authorizedKeys,
        private SshManagedReverseHostReadiness $readiness,
        private TargetTransportBinding $transportBindings,
    ) {}

    private function requireLocalReady(): void
    {
        $gateway = SshManagedReverseGateway::query()->find(1);
        if ($this->readiness->assess($gateway)['state'] !== 'Ready') {
            throw new RuntimeException('Managed Reverse SSH local host is not Ready; inspect Gateway host readiness before enrollment.');
        }
    }

    /** @return array{enrollment:SshManagedReverseEnrollment,token:string} */
    public function begin(
        string $targetId, string $displayName, string $host, int $port,
        string $username, string $hostPublicKey, ?string $aiGuidance = null, ?User $creator = null,
    ): array {
        $endpoint = SshRegisteredEndpoint::fromInput($host, $port, $username);
        $pin = SshHostKeyPin::fromLine($hostPublicKey);
        $targetId = trim($targetId);
        $displayName = trim($displayName);
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1
            || strlen($targetId) > 64 || $displayName === '' || mb_strlen($displayName) > 160
            || ($aiGuidance !== null && mb_strlen($aiGuidance) > Target::AI_GUIDANCE_MAX_LENGTH)) {
            throw new InvalidArgumentException('Invalid managed Reverse SSH Target details.');
        }
        // GET presentation may be stale. A bounded local SSHD/pin check at
        // POST admission is required BEFORE minting any key or Pending Target.
        // The transaction still verifies current enabled/publication policy;
        // no point-in-time probe can guarantee future network availability.
        $this->requireLocalReady();
        // No shelling out from PHP-FPM and no private key transfer to the Target
        // through URLs/logs. The login key is stored only in the existing vault.
        $loginKey = EC::createKey('Ed25519');
        $loginPrivate = $loginKey->toString('OpenSSH');
        $loginPublic = $this->publicKey($loginKey->getPublicKey()->toString('OpenSSH'));
        $token = bin2hex(random_bytes(32));

        $enrollment = DB::transaction(function () use (
            $targetId, $displayName, $aiGuidance, $endpoint, $pin, $loginPrivate, $loginPublic, $token, $creator
        ): SshManagedReverseEnrollment {
            // Locks serialize port ownership even before a Target config exists.
            $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
            if (! $gateway?->enabled || $gateway->publication_pending || ! $this->authorizedKeys->canPublish()
                || ! $this->authorizedKeys->matchesGateway($gateway)) {
                throw new RuntimeException('Managed Reverse SSH is disabled or the approved Gateway host bootstrap is missing.');
            }
            if (Target::query()->where('target_id', $targetId)->exists()
                || SshManagedReverseEnrollment::query()->where('target_id', $targetId)->exists()) {
                throw new InvalidArgumentException('The Target ID is already registered.');
            }
            $port = $this->allocatePort();
            $target = Target::query()->forceCreate([
                'created_by_user_id' => $creator?->getKey(),
                'target_id' => $targetId,
                'display_name' => $displayName,
                'ai_guidance' => $aiGuidance,
                'connector_type' => 'ssh_direct',
                'connection_state' => TargetConnectionState::Pending,
            ]);
            $identity = 'managed-'.bin2hex(random_bytes(12));
            $this->transportBindings->changeReverseLocked($target, $port, $identity);
            $config = SshTargetConfig::query()->create([
                'target_record_id' => $target->getKey(),
                'host' => $endpoint->host,
                'port' => $endpoint->port,
                'username' => $endpoint->username,
                'auth_method' => 'private_key',
                'pinned_host_key' => $pin->canonicalLine(),
                'binding_revision' => 0,
            ]);
            TargetCredential::query()->create([
                'target_record_id' => $target->getKey(),
                'connector_type' => 'ssh_direct',
                'purpose' => SshTargetVault::PURPOSE,
                'encrypted_payload' => $this->vault->seal($target, $config, $loginPrivate, null),
            ]);
            $enrollment = SshManagedReverseEnrollment::query()->create([
                'target_id' => $targetId,
                'target_record_id' => $target->getKey(),
                'listener_port' => $port,
                'tunnel_identity' => $identity,
                'login_public_key' => $loginPublic,
                'token_hash' => hash('sha256', $token),
                'token_expires_at' => now()->addMinutes(10),
                'state' => 'pending',
                'publication_pending' => false,
            ]);
            $this->activity->recordRequired(CorrelationId::current(), 'ssh-managed-reverse-enroll', 'success', $target);

            return $enrollment;
        }, 3);

        return ['enrollment' => $enrollment, 'token' => $token];
    }

    /**
     * On a lost response the caller must request explicit Owner reconciliation;
     * never treat a used token as a safe retry capability.
     *
     * @return array<string,int|string>
     */
    public function claim(string $enrollmentId, string $token, string $publicKey): array
    {
        if (strlen($token) !== 64 || ctype_xdigit($token) === false) {
            throw new InvalidArgumentException('Enrollment authorization rejected.');
        }
        $controlKey = $this->publicKey($publicKey);
        if (! str_starts_with($controlKey, 'ssh-ed25519 ')) {
            throw new InvalidArgumentException('A dedicated Ed25519 control public key is required.');
        }

        return $this->authorizedKeys->withPolicyLock(function () use ($enrollmentId, $token, $controlKey): array {
            $id = DB::transaction(function () use ($enrollmentId, $token, $controlKey): string {
                $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
                $enrollment = SshManagedReverseEnrollment::query()->whereKey($enrollmentId)->lockForUpdate()->first();
                if (! $gateway?->enabled || ! $enrollment || $enrollment->state !== 'pending'
                    || $enrollment->token_expires_at === null
                    || CarbonImmutable::parse($enrollment->token_expires_at)->isPast()
                    || ! is_string($enrollment->token_hash)
                    || ! hash_equals($enrollment->token_hash, hash('sha256', $token))
                    || ! $this->authorizedKeys->canPublish()) {
                    throw new InvalidArgumentException('Enrollment expired, revoked, already used or Gateway unavailable.');
                }
                $keyHash = hash('sha256', $controlKey);
                if (SshManagedReverseEnrollment::query()->where('control_key_hash', $keyHash)->exists()) {
                    throw new InvalidArgumentException('Control key is already assigned to another enrollment.');
                }
                $enrollment->forceFill([
                    'state' => 'claimed',
                    'publication_pending' => true,
                    'control_public_key' => $controlKey,
                    'control_key_hash' => $keyHash,
                    'token_hash' => null,
                    'token_expires_at' => null,
                    'claimed_at' => now(),
                ])->save();

                return (string) $enrollment->getKey();
            }, 3);

            // "claimed" is durable BEFORE publication. A failed or unknown
            // file/DB finalization remains explicitly reconcilable; the token
            // is never replayable and route admission still denies "claimed".
            $this->authorizedKeys->sync();
            $enrollment = SshManagedReverseEnrollment::query()->findOrFail($id);
            $gateway = SshManagedReverseGateway::query()->findOrFail(1);

            return [
                'control_host' => $gateway->control_host,
                'control_port' => $gateway->control_port,
                'control_user' => $gateway->control_user,
                'control_host_key' => $gateway->control_host_key,
                'listener_port' => $enrollment->listener_port,
                'target_port' => $enrollment->target->sshConfig->port,
                'target_username' => $enrollment->login_public_key !== '' ? $enrollment->target->sshConfig->username : '',
                'login_public_key' => $enrollment->login_public_key,
            ];
        });
    }

    /**
     * Owner-confirmed reissue preserves Target identity and encrypted login
     * key, but rotates the enrollment ID as well as control authorization,
     * identity and listener. A previously claimed Target must never reuse its
     * old root-owned state file/unit when the new command is executed.
     * Old ports are permanently quarantined because old -R sessions may live.
     *
     * @return array{enrollment:SshManagedReverseEnrollment,token:string}
     */
    public function reissue(SshManagedReverseEnrollment $original): array
    {
        $this->requireLocalReady();

        return $this->authorizedKeys->withPolicyLock(function () use ($original): array {
            $token = bin2hex(random_bytes(32));
            $enrollment = DB::transaction(function () use ($original, $token): SshManagedReverseEnrollment {
                $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
                if (! $gateway?->enabled || $gateway->publication_pending || ! $this->authorizedKeys->matchesGateway($gateway)) {
                    throw new RuntimeException('Managed Reverse SSH host capability is disabled or mismatched.');
                }
                $target = Target::query()->whereKey($original->target_record_id)->lockForUpdate()->firstOrFail();
                $current = SshManagedReverseEnrollment::query()
                    ->where('target_record_id', $target->getKey())
                    ->whereKey($original->getKey())->lockForUpdate()->firstOrFail();
                $config = SshTargetConfig::query()
                    ->where('target_record_id', $target->getKey())->lockForUpdate()->firstOrFail();
                if ($current->state === 'revoked' || ! $target->usesReverseRoute()) {
                    throw new InvalidArgumentException('Only a selected, non-revoked managed Reverse route can be reissued.');
                }
                // Rotating the control path never opens or rewrites the
                // downstream login credential.
                $newPort = $this->allocatePort();
                DB::table('ssh_reverse_managed_retired_ports')->insert([
                    'listener_port' => $current->listener_port,
                    'target_id' => $current->target_id,
                    'retired_at' => now(),
                ]);
                $identity = 'managed-'.bin2hex(random_bytes(12));
                $this->transportBindings->changeReverseLocked($target, $newPort, $identity);
                DB::table('ssh_direct_target_configs')->where('id', $config->getKey())->update([
                    'verification_attempt_id' => null,
                    'observed_peer_ip' => null,
                    'observed_at' => null,
                    'updated_at' => now(),
                ]);
                // Rotate the PRIMARY enrollment identity, not the stable
                // Target ID. The Target installer namespaces state, Unix
                // tunnel identity and systemd unit by this immutable ID:
                // reusing it would replay a stored old claim response.
                $current->forceFill([
                    'id' => strtolower((string) Str::ulid()),
                    'listener_port' => $newPort,
                    'tunnel_identity' => $identity,
                    'control_public_key' => null,
                    'control_key_hash' => null,
                    'token_hash' => hash('sha256', $token),
                    'token_expires_at' => now()->addMinutes(10),
                    'claimed_at' => null,
                    'activated_at' => null,
                    'state' => 'pending',
                    'publication_pending' => true,
                ])->save();
                $target->forceFill(['last_tested_at' => null])->save();
                $this->activity->recordRequired(
                    CorrelationId::current(), 'ssh-managed-reverse-reissue', 'success', $target,
                );

                return $current;
            }, 3);
            // Do not expose the new one-use command until the old control
            // authorization has been reconciled with the host key reader.
            $this->authorizedKeys->sync();

            return ['enrollment' => $enrollment->fresh(), 'token' => $token];
        });
    }

    public function revoke(SshManagedReverseEnrollment $enrollment): void
    {
        $committed = false;
        try {
            $this->authorizedKeys->withPolicyLock(function () use ($enrollment, &$committed): void {
                $this->revokeLocal($enrollment);
                $committed = true;
                $this->authorizedKeys->sync();
            });
        } finally {
            if (! $committed) {
                // Failure to acquire the publication lock must NEVER
                // prevent local route revocation and Job
                // fencing. A later Owner reconciliation removes host keys.
                $this->revokeLocal($enrollment);
            }
        }
    }

    private function revokeLocal(SshManagedReverseEnrollment $enrollment): void
    {
        DB::transaction(function () use ($enrollment): void {
            SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
            $target = Target::query()->whereKey($enrollment->target_record_id)->lockForUpdate()->firstOrFail();
            $current = SshManagedReverseEnrollment::query()->where('target_record_id', $target->getKey())
                ->whereKey($enrollment->getKey())->lockForUpdate()->firstOrFail();
            $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())
                ->lockForUpdate()->firstOrFail();
            $needsFencing = $current->state !== 'revoked';
            $current->forceFill([
                'state' => 'revoked',
                'publication_pending' => true,
                'revoked_at' => $current->revoked_at ?? now(),
                'token_hash' => null,
                'token_expires_at' => null,
            ])->save();
            if ($needsFencing) {
                $this->transportBindings->changeReverseLocked($target, $target->reverse_listener_port, $target->reverse_tunnel_identity, forceFence: true);
                DB::table('ssh_direct_target_configs')->where('id', $config->getKey())->update([
                    'verification_attempt_id' => null,
                    'observed_peer_ip' => null,
                    'observed_at' => null,
                    'updated_at' => now(),
                ]);
                // Only the transport is revoked. An explicit credential
                // disconnect remains a separate Target operation.
                $target->forceFill(['last_tested_at' => null])->save();
                $this->activity->recordRequired(
                    CorrelationId::current(), 'ssh-managed-reverse-revoke', 'success', $target,
                );
            }
        }, 3);
    }

    /** Reserved by active, legacy and retired routes; also avoid local sockets. */
    private function allocatePort(): int
    {
        $legacyRaw = (string) config('ssh.reverse_approved_routes', '');
        $legacy = json_decode($legacyRaw, true);
        if (trim($legacyRaw) !== '' && ! is_array($legacy)) {
            throw new RuntimeException('Existing operator Reverse SSH route policy is invalid.');
        }
        $ports = array_fill_keys(
            Target::query()->whereNotNull('reverse_listener_port')->pluck('reverse_listener_port')->all(),
            true,
        );
        foreach ($legacy ?? [] as $entry) {
            if (is_array($entry) && is_int($entry['port'] ?? null)) {
                $ports[$entry['port']] = true;
            }
        }
        foreach (SshManagedReverseEnrollment::query()->pluck('listener_port') as $used) {
            $ports[(int) $used] = true;
        }
        foreach (DB::table('ssh_reverse_managed_retired_ports')->pluck('listener_port') as $used) {
            $ports[(int) $used] = true;
        }
        for ($port = self::PORT_START; $port <= self::PORT_END; $port++) {
            if (isset($ports[$port])) {
                continue;
            }
            // Best-effort admission-time check; the later OpenSSH -R request
            // remains authoritative for races or different namespaces.
            $socket = @stream_socket_server('tcp://127.0.0.1:'.$port, $errno, $error);
            if ($socket === false) {
                continue;
            }
            fclose($socket);

            return $port;
        }

        throw new RuntimeException('No available managed Reverse SSH loopback listener ports.');
    }

    private function publicKey(string $text): string
    {
        $fields = preg_split('/\\s+/', trim($text), 3);
        if (! is_array($fields) || count($fields) < 2) {
            throw new InvalidArgumentException('Invalid SSH public key.');
        }

        return SshHostKeyPin::fromLine($fields[0].' '.$fields[1])->canonicalLine();
    }
}
