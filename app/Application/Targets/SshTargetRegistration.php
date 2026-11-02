<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Support\CorrelationId;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

final readonly class SshTargetRegistration
{
    public function __construct(
        private SshTargetVault $vault,
        private ActivityRecorder $activity,
        private SshReverseRoutePolicy $reverseRoutes,
    ) {}

    public function register(
        string $targetId, string $displayName, string $host, int $port,
        string $username, string $hostPublicKey, string $authMethod,
        string $secret, ?string $passphrase, ?string $aiGuidance = null,
        string $routeMode = 'direct', ?int $reversePort = null, ?string $tunnelIdentity = null,
    ): Target {
        $targetId = strtolower(trim($targetId));
        $displayName = trim($displayName);
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1
            || $displayName === '' || mb_strlen($displayName) > 160
            || ! in_array($authMethod, ['password', 'private_key'], true)) {
            throw new InvalidArgumentException('Invalid SSH Target registration fields.');
        }
        $endpoint = SshRegisteredEndpoint::fromInput($host, $port, $username);
        $pin = SshHostKeyPin::fromLine($hostPublicKey);
        $approvedRoute = $this->reverseRoutes->approve($targetId, $routeMode, $reversePort, $tunnelIdentity);
        if ($approvedRoute !== null) {
            $this->reverseRoutes->assertPortAvailable($approvedRoute);
        }

        try {
            return DB::transaction(function () use (
                $targetId, $displayName, $aiGuidance, $endpoint, $pin, $authMethod, $secret, $passphrase,
                $approvedRoute,
            ): Target {
                $target = Target::query()->create([
                    'target_id' => $targetId,
                    'display_name' => $displayName,
                    'ai_guidance' => $aiGuidance === null || trim($aiGuidance) === '' ? null : trim($aiGuidance),
                    'connector_type' => 'ssh_direct',
                    'connection_state' => TargetConnectionState::Disconnected,
                ]);
                $config = SshTargetConfig::query()->create([
                    'target_record_id' => $target->getKey(),
                    'host' => $endpoint->host,
                    'port' => $endpoint->port,
                    'username' => $endpoint->username,
                    'auth_method' => $authMethod,
                    'pinned_host_key' => $pin->canonicalLine(),
                    'route_mode' => $approvedRoute === null ? 'direct' : 'reverse',
                    'reverse_listener_port' => $approvedRoute?->listenerPort,
                    'reverse_tunnel_identity' => $approvedRoute?->tunnelIdentity,
                    'binding_revision' => 0,
                ]);
                TargetCredential::query()->create([
                    'target_record_id' => $target->getKey(),
                    'connector_type' => 'ssh_direct',
                    'purpose' => SshTargetVault::PURPOSE,
                    'encrypted_payload' => $this->vault->seal($target, $config, $secret, $passphrase),
                ]);
                $this->activity->recordRequired(CorrelationId::current(), 'ssh-target-register', 'success', $target);

                return $target;
            });
        } catch (UniqueConstraintViolationException $exception) {
            // The DB unique index closes the race left by the friendly
            // precheck, including if the operator changed port ownership.
            if ($approvedRoute !== null) {
                $this->reverseRoutes->assertPortAvailable($approvedRoute);
            }

            throw new InvalidArgumentException('The SSH Target ID is already registered.', previous: $exception);
        }
    }
}
