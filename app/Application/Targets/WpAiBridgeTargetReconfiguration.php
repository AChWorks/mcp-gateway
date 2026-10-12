<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\WpAiBridge\BridgeDiscoveryException;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeDiscovery;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use App\Support\CorrelationId;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

final readonly class WpAiBridgeTargetReconfiguration
{
    public function __construct(
        private WpAiBridgeDiscovery $discovery,
        private OutboundTargetPolicy $policy,
        private ActivityRecorder $activity,
    ) {}

    public function revision(Target $target): string
    {
        $config = WpAiBridgeTargetConfig::query()
            ->where('target_record_id', $target->getKey())->firstOrFail();

        return TargetConfigurationRevision::make($target, $config->getAttributes(), $this->credential($target));
    }

    /** @param array<string,mixed> $input */
    public function update(Target $target, array $input): bool
    {
        try {
            $url = $this->policy->canonicalBaseUrl((string) $input['base_url']);
        } catch (UnsafeOutboundTarget) {
            throw new TargetConnectorFailure(__('The WordPress origin must be a safe public HTTPS URL.'), 'base_url');
        }

        // This preflight is advisory; identical conditions are checked under
        // the Target row lock before any metadata changes.
        $current = WpAiBridgeTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
        if ($target->connector_type !== 'wp_ai_bridge'
            || ! hash_equals((string) $input['configuration_revision'], $this->revision($target))) {
            throw new TargetConnectorFailure(__('The WordPress Target changed since this form was opened. Reload it.'), 'configuration_revision');
        }
        if ($url === $current->base_url) {
            return false;
        }
        if (! $this->canChangeOrigin($target)) {
            throw new TargetConnectorFailure(
                __('Disconnect and finish WordPress OAuth token revocation/recovery before changing its origin. No existing authorization will be silently transferred.'),
                'base_url',
            );
        }

        // Public HTTPS metadata discovery deliberately happens without a DB
        // lock; the same strict SSRF, DNS and origin checks as registration.
        try {
            $discovered = $this->discovery->discover($url);
        } catch (BridgeDiscoveryException $exception) {
            throw new TargetConnectorFailure(__('New WordPress OAuth/MCP metadata could not be verified safely (:reason).', [
                'reason' => $exception->reason,
            ]), 'base_url');
        }

        try {
            return DB::transaction(function () use ($target, $input, $discovered): bool {
                $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
                $config = WpAiBridgeTargetConfig::query()
                    ->where('target_record_id', $locked->getKey())->lockForUpdate()->firstOrFail();
                $credential = $this->credential($locked, lock: true);
                if ($locked->connector_type !== 'wp_ai_bridge'
                    || ! hash_equals(
                        (string) $input['configuration_revision'],
                        TargetConfigurationRevision::make($locked, $config->getAttributes(), $credential),
                    )) {
                    throw new TargetConnectorFailure(__('The WordPress Target changed during validation. Reload it.'), 'configuration_revision');
                }
                if ($locked->getAttribute('connection_state') !== TargetConnectionState::Disconnected
                    && $locked->getAttribute('connection_state') !== TargetConnectionState::Error) {
                    throw new TargetConnectorFailure(__('Disconnect WordPress before changing its origin.'), 'base_url');
                }
                if ($credential instanceof TargetCredential || $this->hasPendingOauth($locked)) {
                    throw new TargetConnectorFailure(
                        __('An OAuth credential, callback, refresh or revocation is still active. Finish safe disconnect/recovery first.'),
                        'base_url',
                    );
                }

                $nextHash = hash('sha256', $discovered->baseUrl);
                if (DB::table('wp_ai_bridge_target_reservations')->where('target_hash', $nextHash)->exists()) {
                    throw new TargetConnectorFailure(__('This WordPress origin is being registered by another Target.'), 'base_url');
                }

                $config->forceFill([
                    'base_url' => $discovered->baseUrl,
                    'base_url_hash' => $nextHash,
                    'mcp_resource_url' => $discovered->resourceUrl,
                    'oauth_issuer_url' => $discovered->issuerUrl,
                    'oauth_authorization_url' => $discovered->authorizationUrl,
                    'oauth_token_url' => $discovered->tokenUrl,
                    'oauth_revocation_url' => $discovered->revocationUrl,
                ])->save();
                $locked->forceFill([
                    'connection_state' => TargetConnectionState::Disconnected,
                    'last_error_code' => null,
                    'last_tested_at' => null,
                    'connected_at' => null,
                    'last_success_at' => null,
                    'last_failure_at' => null,
                    'last_failure_code' => null,
                ])->save();
                $this->activity->recordRequired(
                    CorrelationId::current(), 'wordpress-origin-reconfigure', 'success', $locked,
                );

                return true;
            });
        } catch (UniqueConstraintViolationException) {
            throw new TargetConnectorFailure(__('That WordPress origin is already assigned to a Target.'), 'base_url');
        }
    }

    private function canChangeOrigin(Target $target): bool
    {
        return in_array($target->getAttribute('connection_state'), [TargetConnectionState::Disconnected, TargetConnectionState::Error], true)
            && ! $this->credential($target) instanceof TargetCredential
            && ! $this->hasPendingOauth($target);
    }

    private function credential(Target $target, bool $lock = false): ?TargetCredential
    {
        $query = TargetCredential::query()->where('target_record_id', $target->getKey())
            ->where('connector_type', 'wp_ai_bridge');

        return ($lock ? $query->lockForUpdate() : $query)->first();
    }

    private function hasPendingOauth(Target $target): bool
    {
        foreach ([
            'wp_ai_bridge_oauth_flows', 'wp_ai_bridge_refresh_intents', 'wp_ai_bridge_revocation_intents',
        ] as $table) {
            if (DB::table($table)->where('target_record_id', $target->getKey())->exists()) {
                return true;
            }
        }

        return false;
    }
}
