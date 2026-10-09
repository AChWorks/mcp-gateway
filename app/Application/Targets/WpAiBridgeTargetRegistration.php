<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeDiscovery;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * Register an initial, disconnected WordPress Target without assigning any
 * credentials. WordPress discovery/endpoint identity belongs to this connector,
 * not to the shared Target model or the global Target namespace.
 */
final readonly class WpAiBridgeTargetRegistration
{
    public function __construct(private WpAiBridgeDiscovery $discovery) {}

    public function register(string $targetId, string $displayName, string $baseUrl): Target
    {
        $targetId = strtolower(trim($targetId));
        $displayName = trim($displayName);

        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            throw new InvalidArgumentException('Invalid Target ID; use a lowercase slug of at most 64 characters.');
        }

        if ($displayName === '' || mb_strlen($displayName) > 160) {
            throw new InvalidArgumentException('Target display name must be between 1 and 160 characters.');
        }

        // Existing discovery enforces HTTPS, DNS pinning, public outbound policy,
        // bounded response sizes, same-origin OAuth URLs and supported protocols.
        $metadata = $this->discovery->discover($baseUrl);
        $hash = hash('sha256', $metadata->baseUrl);

        try {
            return DB::transaction(static function () use ($targetId, $displayName, $metadata, $hash): Target {
                // Connector-scoped reservation prevents same-endpoint registration
                // racing against future reassignment, but never blocks SSH/Agent
                // Targets at the same host.
                DB::table('wp_ai_bridge_target_reservations')->insert([
                    'target_hash' => $hash,
                    'target_url' => $metadata->baseUrl,
                    'owner_target_id' => $targetId,
                    'target_record_id' => null,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                $target = Target::query()->create([
                    'target_id' => $targetId,
                    'display_name' => $displayName,
                    'connector_type' => 'wp_ai_bridge',
                    'connection_state' => TargetConnectionState::Disconnected,
                ]);

                WpAiBridgeTargetConfig::query()->create([
                    'target_record_id' => $target->getKey(),
                    'base_url' => $metadata->baseUrl,
                    'base_url_hash' => $hash,
                    'mcp_resource_url' => $metadata->resourceUrl,
                    'oauth_issuer_url' => $metadata->issuerUrl,
                    'oauth_authorization_url' => $metadata->authorizationUrl,
                    'oauth_token_url' => $metadata->tokenUrl,
                    'oauth_revocation_url' => $metadata->revocationUrl,
                ]);

                DB::table('wp_ai_bridge_target_reservations')
                    ->where('target_hash', $hash)
                    ->delete();

                return $target;
            });
        } catch (UniqueConstraintViolationException $exception) {
            throw new InvalidArgumentException(
                'The Target ID or canonical WordPress endpoint is already registered or reserved.',
                previous: $exception,
            );
        }
    }
}
