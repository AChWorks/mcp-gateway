<?php

namespace App\Infrastructure\Connectors\ArvanCloud;

use App\Application\Targets\TargetConfigurationRevision;
use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorResult;
use App\Application\Targets\TargetEndpointPreflight;
use App\Application\Targets\TargetEnrollmentPreflight;
use App\Application\Targets\TargetOperationGate;
use App\Application\Targets\TargetPreflightResult;
use App\Application\Targets\TargetTransportBinding;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\Relay\ConnectionRelayUnavailable;
use App\Infrastructure\Http\Api\ApiHttpTransport;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;
use App\Models\User;
use App\Support\CorrelationId;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use RuntimeException;

/**
 * One registered Arvan HTTP API root per Target. Distinct products/regions may
 * register separate Targets, never a request-supplied host or credential.
 */
final readonly class ArvanApiTargetAdapter implements TargetConnectorAdapter, TargetEnrollmentPreflight
{
    public function __construct(
        private OutboundTargetPolicy $policy,
        private ArvanApiTargetVault $vault,
        private ApiHttpTransport $transport,
        private ActivityRecorder $activity,
        private TargetEndpointPreflight $preflight,
        private TargetTransportBinding $bindings,
        private ConnectionRelayRoutes $relays,
    ) {}

    public function type(): string
    {
        return 'arvancloud';
    }

    public function registrationRules(): array
    {
        return [
            'api_base_url' => ['required', 'string', 'url:https', 'max:1024'],
            'api_spec_url' => ['nullable', 'string', 'url:https', 'max:1024'],
            'api_probe_path' => ['nullable', 'string', 'max:1024', 'starts_with:/'],
            'api_key' => ['required', 'string', 'max:4096'],
        ];
    }

    public function safeOldInputFields(): array
    {
        return ['api_base_url', 'api_spec_url', 'api_probe_path'];
    }

    public function preflightRules(): array
    {
        return ['api_base_url' => ['required', 'string', 'url:https', 'max:1024']];
    }

    public function preflight(array $input): TargetPreflightResult
    {
        try {
            return $this->preflight->publicHttpsOrigin((string) $input['api_base_url']);
        } catch (UnsafeOutboundTarget|OutboundRequestException $exception) {
            throw new TargetConnectorFailure(
                __('ArvanCloud endpoint preflight failed. Check the public HTTPS DNS/URL.'),
                'api_base_url', 'unsafe_target',
                ['failure_origin' => 'gateway_admission', 'pre_dispatch' => true],
            );
        }
    }

    public function register(array $input, ?User $creator = null): Target
    {
        try {
            $base = $this->canonical((string) $input['api_base_url']);
            $spec = $this->validatedSpec($input['api_spec_url'] ?? null);
            $probe = $this->validatedProbe($input['api_probe_path'] ?? null);
            $key = (string) $input['api_key'];

            return DB::transaction(function () use ($input, $base, $spec, $probe, $key, $creator): Target {
                $target = Target::query()->forceCreate([
                    'created_by_user_id' => $creator?->getKey(),
                    'target_id' => (string) $input['target_id'],
                    'display_name' => (string) $input['display_name'],
                    'ai_guidance' => $input['ai_guidance'] ?? null,
                    'connector_type' => $this->type(),
                    'connection_state' => TargetConnectionState::Disconnected,
                ]);
                $this->bindings->onRegistration($target, $input['connection_relay_id'] ?? null);
                $config = ArvanApiTargetConfig::query()->create([
                    'target_record_id' => $target->getKey(),
                    'base_url' => $base,
                    'spec_url' => $spec,
                    'probe_path' => $probe,
                ]);
                TargetCredential::query()->create([
                    'target_record_id' => $target->getKey(),
                    'connector_type' => $this->type(),
                    'purpose' => ArvanApiTargetVault::PURPOSE,
                    'encrypted_payload' => $this->validatedSeal($target, $config, $key),
                ]);
                $this->activity->recordRequired(CorrelationId::current(), 'arvan-target-register', 'success', $target);

                return $target;
            });
        } catch (ConnectionRelayUnavailable) {
            throw new TargetConnectorFailure(__('The selected Connection Relay is disabled or no longer exists.'), 'connection_relay_id', 'relay_unavailable');
        } catch (UniqueConstraintViolationException $exception) {
            throw new TargetConnectorFailure(__('Target ID is already in use.'), 'target_id', 'invalid_input', []);
        } catch (TargetConnectorFailure $exception) {
            throw $exception;
        } catch (UnsafeOutboundTarget|OutboundRequestException $exception) {
            throw new TargetConnectorFailure(__('ArvanCloud endpoint could not be safely verified.'), 'api_base_url', 'unsafe_target', []);
        } catch (InvalidArgumentException|RuntimeException $exception) {
            throw new TargetConnectorFailure(__('ArvanCloud endpoint, probe or API credential is invalid.'), 'api_base_url', 'invalid_input', []);
        }
    }

    public function registrationRequiresPassword(array $input): bool
    {
        return true;
    }

    public function registrationStatus(): string
    {
        return __('ArvanCloud API Target saved with an encrypted key. Use the unauthenticated HTTPS endpoint check now, or configure an optional known read-only GET probe to verify the key.');
    }

    public function configurationRules(Target $target): array
    {
        return [
            'configuration_revision' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]{64}$/D'],
            'api_base_url' => ['required', 'string', 'url:https', 'max:1024'],
            'api_spec_url' => ['nullable', 'string', 'url:https', 'max:1024'],
            'api_probe_path' => ['nullable', 'string', 'max:1024', 'starts_with:/'],
            'api_key' => ['nullable', 'string', 'max:4096'],
        ];
    }

    public function configurationRevision(Target $target): string
    {
        // Include the persisted DB-default connection state even immediately
        // after Target creation (an in-memory model may not have hydrated it).
        $stored = Target::query()->whereKey($target->getKey())->firstOrFail();
        $config = $this->config($stored);
        $credential = $this->credential($stored);

        return TargetConfigurationRevision::make($stored, [
            'base_url' => $config->base_url,
            'spec_url' => $config->spec_url,
            'probe_path' => $config->probe_path,
        ], $credential);
    }

    public function updateConfiguration(Target $target, array $input): TargetConnectorResult
    {
        try {
            $base = $this->canonical((string) $input['api_base_url']);
            $spec = $this->validatedSpec($input['api_spec_url'] ?? null);
            $probe = $this->validatedProbe($input['api_probe_path'] ?? null);

            DB::transaction(function () use ($target, $input, $base, $spec, $probe): void {
                $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
                $config = $this->config($locked);
                $credential = $this->credential($locked);
                if (! hash_equals($this->configurationRevision($locked), (string) $input['configuration_revision'])) {
                    throw new InvalidArgumentException('Target configuration changed. Reload to avoid overwriting current credentials.');
                }
                $changedBase = ! hash_equals($config->base_url, $base);
                $changedProbe = $config->probe_path !== $probe;
                $newKey = (string) ($input['api_key'] ?? '');
                if ($changedBase && $newKey === '') {
                    throw new TargetConnectorFailure(
                        __('Changing the API base URL requires a new Machine User API key. Enter it below and save again.'),
                        'api_key', 'invalid_input',
                    );
                }
                $config->forceFill(['base_url' => $base, 'spec_url' => $spec, 'probe_path' => $probe])->save();
                if ($newKey !== '') {
                    $sealed = $this->validatedSeal($locked, $config, $newKey);
                    if ($credential instanceof TargetCredential) {
                        $credential->forceFill(['encrypted_payload' => $sealed])->save();
                    } else {
                        TargetCredential::query()->create([
                            'target_record_id' => $locked->getKey(),
                            'connector_type' => $this->type(),
                            'purpose' => ArvanApiTargetVault::PURPOSE,
                            'encrypted_payload' => $sealed,
                        ]);
                    }
                }
                if ($changedBase || $changedProbe || $newKey !== '') {
                    $locked->forceFill(['connection_state' => TargetConnectionState::Disconnected, 'connected_at' => null])->save();
                }
                $this->activity->recordRequired(CorrelationId::current(), 'arvan-target-configure', 'success', $locked);
            });

            return new TargetConnectorResult(statusMessage: __('ArvanCloud API settings saved. Check the HTTPS endpoint without a key, or configure an optional known read-only GET probe to verify authentication. Previous connection verification is reset after changing the API root, probe or key.'));
        } catch (TargetConnectorFailure $exception) {
            throw $exception;
        } catch (UnsafeOutboundTarget|OutboundRequestException $exception) {
            throw new TargetConnectorFailure(__('API endpoint is unsafe or unreachable.'), 'api_base_url', 'unsafe_target', []);
        } catch (InvalidArgumentException|RuntimeException $exception) {
            throw new TargetConnectorFailure($exception->getMessage(), 'configuration_revision', 'invalid_input', []);
        }
    }

    public function connect(Target $target): TargetConnectorResult
    {
        return $this->test($target);
    }

    public function reconnect(Target $target): TargetConnectorResult
    {
        return $this->test($target);
    }

    public function disconnect(Target $target): TargetConnectorResult
    {
        DB::transaction(function () use ($target): void {
            // All changes that invalidate a probe take the same Target row
            // lock used for conditional probe settlement, never across I/O.
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
            TargetCredential::query()->where('target_record_id', $locked->getKey())
                ->where('connector_type', $this->type())
                ->where('purpose', ArvanApiTargetVault::PURPOSE)->delete();
            $locked->forceFill(['connection_state' => TargetConnectionState::Disconnected, 'connected_at' => null])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'arvan-target-disconnect', 'success', $locked);
        });

        return new TargetConnectorResult(statusMessage: __('Gateway deleted its local ArvanCloud credential. Revoke the Machine User API key in ArvanCloud separately if required.'));
    }

    /**
     * Check the registered HTTPS API base without using any credential.
     * HEAD is intentional: an HTTP 401/403/404/405 still proves that a TLS
     * peer responded, but NEVER authenticates the Machine User or updates the
     * stored connection state. No operator-supplied method/path is executed.
     */
    public function checkReachability(Target $target): TargetConnectorResult
    {
        $this->requireUnpaused($target);
        $base = $this->config($target)->base_url;

        try {
            $this->requireUnpaused($target);
            $response = $this->transport->request($base, 'HEAD', '/', relay: $this->relays->httpRouteForTarget($target));

            // A concurrent Pause, removal or API-root replacement invalidates
            // even this read-only observation before it can be displayed.
            $this->assertReachabilityStillCurrent($target, $base);

            return new TargetConnectorResult(statusMessage: __(
                'The HTTPS server for the registered API root responded to an unauthenticated HEAD request (HTTP :status). This confirms HTTPS reachability only, not API path availability; the API key was NOT tested and the authenticated connection state was NOT changed. An HTTP error may mean the base path does not accept HEAD.',
                ['status' => $response->status],
            ));
        } catch (TargetConnectorFailure $exception) {
            throw $exception;
        } catch (UnsafeOutboundTarget $exception) {
            throw new TargetConnectorFailure(
                __('The registered API endpoint is not allowed by the Gateway HTTPS/public-address policy. Check the configured API root and DNS; the API key was not tested.'),
                null, 'unsafe_target',
            );
        } catch (OutboundRequestException $exception) {
            $status = $exception->details['http_status'] ?? null;
            if ($exception->reason === 'unsafe_redirect'
                && is_int($status) && $status >= 300 && $status < 400) {
                // The pinned HTTPS peer already answered. For this one
                // credential-free HEAD observation, a 3xx means reachable,
                // NOT an authenticated connection or an approved redirect.
                // The shared transport still rejects 3xx for every actual
                // authenticated API operation and never follows Location.
                $this->assertReachabilityStillCurrent($target, $base);

                return new TargetConnectorResult(statusMessage: __(
                    'The registered HTTPS API root responded to an unauthenticated HEAD request with HTTP :status (redirect). HTTPS reachability was observed, but the redirect was NOT followed. Check that the API root points to the intended product API path. No API key was sent, authentication was NOT tested, and the connection state was NOT changed.',
                    ['status' => $status],
                ));
            }

            throw new TargetConnectorFailure(
                __('The Gateway could not complete an HTTPS HEAD check of the registered API base (:reason). Check DNS, TLS, network access and the API root. No API key was sent and authentication was not tested.', [
                    'reason' => $exception->reason,
                ]),
                null, $exception->reason, $exception->details,
            );
        }
    }

    private function assertReachabilityStillCurrent(Target $target, string $base): void
    {
        if (TargetOperationGate::isPaused($target)
            || (int) Target::query()->whereKey($target->getKey())->value('transport_revision') !== (int) $target->transport_revision
            || ! hash_equals($base, $this->config($target)->base_url)) {
            throw new TargetConnectorFailure(
                __('The API endpoint or route changed, or the Target was paused during the reachability check. Reload and check the current Target.'),
                null, 'endpoint_check_stale',
            );
        }
    }

    public function test(Target $target): TargetConnectorResult
    {
        // Connect, Reconnect and Test must share ONE fresh per-dispatch pause
        // boundary. Local Disconnect/credential recovery remains available.
        $this->requireUnpaused($target);
        $config = $this->config($target);
        if ($config->probe_path === null) {
            throw new TargetConnectorFailure(
                __('No authenticated GET probe is configured. You can check HTTPS reachability without an API key, or ask an authorized Target configuration editor to save a known read-only GET path to verify the key.'),
                'api_probe_path', 'probe_not_configured',
            );
        }
        try {
            $credential = $this->credential($target)
                ?? throw new RuntimeException('ArvanCloud credential was disconnected.');
            $key = $this->vault->open($target, $config, $credential);
            // Recheck immediately before invoking the transport. A pause or
            // removal after the initial form load cannot dispatch a new probe.
            $this->requireUnpaused($target);
            $response = $this->transport->request(
                $config->base_url, 'GET', $config->probe_path, [],
                null, ['Authorization' => 'Apikey '.$key],
                relay: $this->relays->httpRouteForTarget($target),
            );
            if ($response->status < 200 || $response->status >= 300) {
                $message = match ($response->status) {
                    401, 403 => __('The configured authenticated GET probe returned HTTP :status. Authorization was not confirmed; check the Machine User key, its product scopes and the selected GET path.', ['status' => $response->status]),
                    404, 405 => __('The configured authenticated GET probe returned HTTP :status. Verify that this read-only GET path exists under the current API root; the API key was not verified.', ['status' => $response->status]),
                    default => __('The configured authenticated GET probe returned HTTP :status. Authentication was not verified; check the provider status and configured GET endpoint.', ['status' => $response->status]),
                };
                throw new TargetConnectorFailure($message, null, 'upstream_http_error', ['http_status' => $response->status]);
            }

            // HTTP I/O happened WITHOUT a DB lock. The result is evidence
            // only for the exact credential/configuration used to dispatch.
            // The same short Target row lock serializes rotation, Disconnect
            // and this conditional health update.
            DB::transaction(function () use ($target, $config, $credential): void {
                $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->first();
                if (! $locked instanceof Target || TargetOperationGate::isPaused($locked)) {
                    throw new TargetConnectorFailure(
                        __('The Target was paused or removed during the probe; no connection state was changed.'),
                        null, 'probe_stale',
                    );
                }
                $currentConfig = $this->config($locked);
                $currentCredential = $this->credential($locked);
                if ((int) $locked->transport_revision !== (int) $target->transport_revision
                    || ! hash_equals($config->base_url, $currentConfig->base_url)
                    || $config->probe_path !== $currentConfig->probe_path
                    || $config->spec_url !== $currentConfig->spec_url
                    || ! $currentCredential instanceof TargetCredential
                    || ! hash_equals((string) $credential->getKey(), (string) $currentCredential->getKey())
                    || ! hash_equals((string) $credential->encrypted_payload, (string) $currentCredential->encrypted_payload)) {
                    throw new TargetConnectorFailure(
                        __('The API configuration, route or key changed during the probe. Reload and verify the current credentials.'),
                        null, 'probe_stale',
                    );
                }

                $locked->forceFill([
                    'connection_state' => TargetConnectionState::Connected,
                    'connected_at' => now(),
                    'last_tested_at' => now(),
                    'last_success_at' => now(),
                    'last_error_code' => null,
                ])->save();
            });

            return new TargetConnectorResult(statusMessage: __('Authenticated ArvanCloud GET probe succeeded.'));
        } catch (TargetConnectorFailure $exception) {
            throw $exception;
        } catch (OutboundRequestException $exception) {
            throw new TargetConnectorFailure(
                __('ArvanCloud connection test failed: :reason', ['reason' => $exception->reason]),
                null, $exception->reason, $exception->details,
            );
        } catch (RuntimeException $exception) {
            throw new TargetConnectorFailure(
                __('ArvanCloud API key is unavailable or no longer valid locally.'),
                null, 'credential_unavailable', [],
            );
        }
    }

    private function requireUnpaused(Target $target): void
    {
        if (TargetOperationGate::isPaused($target)) {
            throw new TargetConnectorFailure(
                __('Resume Target operations before starting an authenticated ArvanCloud probe.'),
                null, 'target_paused',
            );
        }
    }

    public function adminDetails(Target $target): array
    {
        return [
            'arvanConfig' => ArvanApiTargetConfig::query()->where('target_record_id', $target->getKey())->first(),
            'arvanHasCredential' => $this->credential($target) instanceof TargetCredential,
        ];
    }

    public function publicMetadata(Target $target): array
    {
        $config = ArvanApiTargetConfig::query()->where('target_record_id', $target->getKey())->first();

        return $config instanceof ArvanApiTargetConfig ? [
            'arvan_api' => ['base_url' => $config->base_url, 'has_openapi_spec' => $config->spec_url !== null],
        ] : [];
    }

    public function hasPendingDeletion(Target $target): bool
    {
        return false;
    }

    private function config(Target $target): ArvanApiTargetConfig
    {
        return ArvanApiTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
    }

    private function credential(Target $target): ?TargetCredential
    {
        return TargetCredential::query()->where('target_record_id', $target->getKey())
            ->where('connector_type', $this->type())
            ->where('purpose', ArvanApiTargetVault::PURPOSE)->first();
    }

    private function canonical(string $url): string
    {
        return $this->policy->canonicalBaseUrl($url);
    }

    private function validatedSpec(mixed $url): ?string
    {
        try {
            return $this->nullableUrl($url);
        } catch (UnsafeOutboundTarget|OutboundRequestException|InvalidArgumentException|RuntimeException) {
            throw new TargetConnectorFailure(
                __('OpenAPI description URL must be a valid public HTTPS URL without credentials, query parameters or fragments.'),
                'api_spec_url', 'invalid_input',
            );
        }
    }

    private function validatedProbe(mixed $path): ?string
    {
        try {
            return $this->probe($path);
        } catch (InvalidArgumentException) {
            throw new TargetConnectorFailure(
                __('Read-only GET probe path must start with / and cannot contain a query, fragment or path traversal.'),
                'api_probe_path', 'invalid_input',
            );
        }
    }

    private function validatedSeal(Target $target, ArvanApiTargetConfig $config, string $key): string
    {
        // Distinguish bad submitted material from an actual Gateway vault
        // failure, without reflecting either the key or a crypto exception.
        if ($key === '' || strlen($key) > 4096 || preg_match('/[\x00-\x20\x7f]/', $key) === 1) {
            throw new TargetConnectorFailure(
                __('Machine User API key format is invalid. Paste a key without spaces or line breaks.'),
                'api_key', 'invalid_input',
            );
        }

        try {
            return $this->vault->seal($target, $config, $key);
        } catch (RuntimeException) {
            throw new TargetConnectorFailure(
                __('Gateway could not securely store this API key. No new key was saved; check Gateway encryption diagnostics before retrying.'),
                'configuration', 'credential_storage_failed',
            );
        }
    }

    private function nullableUrl(mixed $url): ?string
    {
        return is_string($url) && trim($url) !== '' ? $this->canonical($url) : null;
    }

    private function probe(mixed $path): ?string
    {
        if (! is_string($path) || trim($path) === '') {
            return null;
        }
        if (! str_starts_with($path, '/') || str_starts_with($path, '//')
            || preg_match('/[?#\x00-\x20\x7f]/', $path) === 1
            || str_contains($path, '..')) {
            throw new InvalidArgumentException('Read-only probe path is invalid.');
        }

        return $path;
    }
}
