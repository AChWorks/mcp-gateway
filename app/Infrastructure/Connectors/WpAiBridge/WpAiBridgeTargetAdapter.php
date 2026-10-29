<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorResult;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetReconfiguration;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Support\OperationDiagnostics;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/** WordPress-specific work stays behind the common Target lifecycle boundary. */
final readonly class WpAiBridgeTargetAdapter implements TargetConnectorAdapter
{
    public function __construct(private Container $container) {}

    public function type(): string
    {
        return 'wp_ai_bridge';
    }

    public function registrationRules(): array
    {
        return [
            'base_url' => ['required', 'string', 'url:https', 'max:2048'],
        ];
    }

    public function safeOldInputFields(): array
    {
        return ['base_url'];
    }

    public function register(array $input): Target
    {
        try {
            return $this->container->make(WpAiBridgeTargetRegistration::class)->register(
                (string) $input['target_id'],
                (string) $input['display_name'],
                (string) $input['base_url'],
                $input['ai_guidance'] ?? null,
            );
        } catch (BridgeDiscoveryException $exception) {
            throw new TargetConnectorFailure(
                OperationDiagnostics::summary($exception->reason, $exception->diagnostics),
                'base_url',
                $exception->reason,
                $exception->diagnostics,
            );
        } catch (InvalidArgumentException) {
            throw new TargetConnectorFailure(
                __('The Target ID or WordPress endpoint is invalid or already registered.'),
                'target_id',
            );
        }
    }

    public function registrationStatus(): string
    {
        return __('WordPress Target registered. Connection authorization is not yet configured.');
    }

    public function configurationRules(Target $target): array
    {
        return [
            'configuration_revision' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]{64}$/D'],
            'base_url' => ['required', 'string', 'url:https', 'max:2048'],
        ];
    }

    public function configurationRevision(Target $target): string
    {
        return $this->container->make(WpAiBridgeTargetReconfiguration::class)->revision($target);
    }

    public function updateConfiguration(Target $target, array $input): TargetConnectorResult
    {
        $changed = $this->container->make(WpAiBridgeTargetReconfiguration::class)->update($target, $input);

        return new TargetConnectorResult(statusMessage: $changed
            ? __('WordPress origin updated after safe metadata discovery. Reauthorize this Target with WordPress OAuth before using it.')
            : __('No WordPress origin change was necessary.'));
    }

    public function connect(Target $target): TargetConnectorResult
    {
        try {
            return new TargetConnectorResult(
                redirectUrl: $this->container->make(WpAiBridgeTargetConnectionService::class)->begin($target),
                authorizedOrigin: (string) WpAiBridgeTargetConfig::query()
                    ->where('target_record_id', $target->getKey())->value('base_url'),
            );
        } catch (WpAiBridgeTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->connectionFailureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function reconnect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(WpAiBridgeTargetConnectionService::class)->disconnect($target);

            return new TargetConnectorResult(
                redirectUrl: $this->container->make(WpAiBridgeTargetConnectionService::class)->begin($target),
                authorizedOrigin: (string) WpAiBridgeTargetConfig::query()
                    ->where('target_record_id', $target->getKey())->value('base_url'),
            );
        } catch (WpAiBridgeTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->connectionFailureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function disconnect(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(WpAiBridgeTargetConnectionService::class)->disconnect($target);

            return new TargetConnectorResult(statusMessage: __('WordPress Target disconnected after confirmed credential revocation.'));
        } catch (WpAiBridgeTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->connectionFailureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    public function test(Target $target): TargetConnectorResult
    {
        try {
            $this->container->make(WpAiBridgeTargetConnectionService::class)->testConnection($target);

            return new TargetConnectorResult(statusMessage: __('WordPress metadata is reachable and compatible.'));
        } catch (WpAiBridgeTargetConnectionException $exception) {
            throw new TargetConnectorFailure($this->connectionFailureMessage($exception), null, $exception->reason, $exception->diagnostics);
        }
    }

    /** @return array<string, mixed> */
    public function adminDetails(Target $target): array
    {
        $id = $target->getKey();
        $credential = TargetCredential::query()
            ->where('target_record_id', $id)->where('connector_type', $this->type())
            ->where('purpose', 'wordpress_oauth')->first(['id']);

        return [
            'wpConfig' => WpAiBridgeTargetConfig::query()->where('target_record_id', $id)->first(),
            'hasCredential' => $credential !== null,
            // Read-only, non-secret expiry and generation help avoid offering
            // a cancellation action when local proof already makes it impossible.
            'credentialMetadata' => $credential === null ? null : DB::table('wp_ai_bridge_credential_metadata')
                ->where('credential_id', $credential->getKey())
                ->first(['credential_id', 'generation', 'access_expires_at']),
            'revocationIntent' => DB::table('wp_ai_bridge_revocation_intents')
                ->where('target_record_id', $id)
                ->first(['id', 'kind', 'phase', 'credential_id', 'generation', 'token_total', 'token_confirmed', 'created_at', 'updated_at']),
            'revocationPending' => DB::table('wp_ai_bridge_revocation_intents')
                ->where('target_record_id', $id)->exists(),
            'oauthFlowPending' => DB::table('wp_ai_bridge_oauth_flows')
                ->where('target_record_id', $id)->exists(),
            'refreshIntent' => DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $id)->first(['id', 'created_at']),
            'refreshPending' => DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $id)->exists(),
        ];
    }

    public function publicMetadata(Target $target): array
    {
        return [];
    }

    public function hasPendingDeletion(Target $target): bool
    {
        $id = $target->getKey();

        return DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $id)->exists()
            || DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $id)->exists()
            || DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $id)->exists();
    }

    /** Used by the WordPress-only attested refresh-reconciliation workflow. */
    public function connectionFailureMessage(WpAiBridgeTargetConnectionException $exception): string
    {
        return match ($exception->reason) {
            'unsafe_target' => OperationDiagnostics::summary('unsafe_target', $exception->diagnostics),
            'missing_bridge', 'incompatible_metadata' => __('WordPress connector OAuth/MCP metadata is missing or incompatible.'),
            'already_connected' => __('Disconnect or reconnect the existing credential before starting a new authorization.'),
            'callback_pending' => __('An OAuth callback is being completed. Check its result before retrying.'),
            'revocation_pending', 'revocation_failed', 'revocation_conflict', 'revocation_uncertain' => __('WordPress disconnect is not confirmed. Open recovery details; only a proven never-sent revoke can be retried.'),
            'cancel_not_safe', 'cancel_verification_unavailable', 'cancel_verification_failed' => __('Cancellation was not verified. The existing authorization stays blocked; review the safe recovery options.'),
            'refresh_settling' => __('The refresh recovery window is still active. Wait before reconciling.'),
            'refresh_conflict' => __('The pending refresh changed. Reload Target details before any reconciliation.'),
            'credential_unavailable' => __('Stored credential cannot be verified. Restore the matching encryption key before retrying.'),
            'network_failure', 'tls_failure', 'remote_failure' => __('WordPress cannot be reached securely right now. Retry after checking connectivity.'),
            default => __('The WordPress Target operation could not be completed safely. Check its status and retry.'),
        };
    }
}
