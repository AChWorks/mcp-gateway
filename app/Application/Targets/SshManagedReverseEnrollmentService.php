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
use App\Support\CorrelationId;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
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
    ) {}

    /** @return array{enrollment:SshManagedReverseEnrollment,token:string} */
    public function begin(
        string $targetId, string $displayName, string $host, int $port,
        string $username, string $hostPublicKey, ?string $aiGuidance = null,
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
        // No shelling out from PHP-FPM and no private key transfer to the Target
        // through URLs/logs. The login key is stored only in the existing vault.
        $loginKey = EC::createKey('Ed25519');
        $loginPrivate = $loginKey->toString('OpenSSH');
        $loginPublic = $this->publicKey($loginKey->getPublicKey()->toString('OpenSSH'));
        $token = bin2hex(random_bytes(32));

        $enrollment = DB::transaction(function () use (
            $targetId, $displayName, $aiGuidance, $endpoint, $pin, $loginPrivate, $loginPublic, $token
        ): SshManagedReverseEnrollment {
            // Locks serialize port ownership even before a Target config exists.
            $gateway = SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
            if (! $gateway?->enabled || ! $this->authorizedKeys->canPublish()
                || ! $this->authorizedKeys->matchesGateway($gateway)) {
                throw new RuntimeException('Managed Reverse SSH is disabled or the approved Gateway host bootstrap is missing.');
            }
            if (Target::query()->where('target_id', $targetId)->exists()
                || SshManagedReverseEnrollment::query()->where('target_id', $targetId)->exists()) {
                throw new InvalidArgumentException('The Target ID is already registered.');
            }
            $legacyRaw = (string) config('ssh.reverse_approved_routes', '');
            $legacy = json_decode($legacyRaw, true);
            if (trim($legacyRaw) !== '' && ! is_array($legacy)) {
                throw new RuntimeException('Existing operator Reverse SSH route policy is invalid.');
            }
            $ports = array_fill_keys(
                SshTargetConfig::query()->where('route_mode', 'reverse')->pluck('reverse_listener_port')->all(),
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
            $port = null;
            for ($candidate = self::PORT_START; $candidate <= self::PORT_END; $candidate++) {
                if (! isset($ports[$candidate])) {
                    $port = $candidate;
                    break;
                }
            }
            if ($port === null) {
                throw new RuntimeException('No available managed Reverse SSH listener ports.');
            }
            $target = Target::query()->create([
                'target_id' => $targetId,
                'display_name' => $displayName,
                'ai_guidance' => $aiGuidance,
                'connector_type' => 'ssh_direct',
                'connection_state' => TargetConnectionState::Pending,
            ]);
            $identity = 'managed-'.bin2hex(random_bytes(12));
            $config = SshTargetConfig::query()->create([
                'target_record_id' => $target->getKey(),
                'host' => $endpoint->host,
                'port' => $endpoint->port,
                'username' => $endpoint->username,
                'auth_method' => 'private_key',
                'pinned_host_key' => $pin->canonicalLine(),
                'route_mode' => 'reverse',
                'reverse_listener_port' => $port,
                'reverse_tunnel_identity' => $identity,
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
                'control_public_key' => $controlKey,
                'control_key_hash' => $keyHash,
                'token_hash' => null,
                'token_expires_at' => null,
                'claimed_at' => now(),
            ])->save();

            return (string) $enrollment->getKey();
        }, 3);

        // Filesystem publication can fail after the token is consumed. Keep
        // "claimed" (never "connected") and let an Owner explicitly reconcile.
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
            'target_username' => $enrollment->target->sshConfig->username,
            'login_public_key' => $enrollment->login_public_key,
        ];
    }

    public function revoke(SshManagedReverseEnrollment $enrollment): void
    {
        DB::transaction(function () use ($enrollment): void {
            SshManagedReverseGateway::query()->whereKey(1)->lockForUpdate()->first();
            $current = SshManagedReverseEnrollment::query()->whereKey($enrollment->getKey())->lockForUpdate()->firstOrFail();
            if ($current->state !== 'revoked') {
                $current->forceFill([
                    'state' => 'revoked', 'revoked_at' => now(),
                    'token_hash' => null, 'token_expires_at' => null,
                ])->save();
            }
        }, 3);
        $this->authorizedKeys->sync();
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
