<?php

namespace App\Infrastructure\Connectors\ArvanCloud;

use App\Application\Targets\TargetConfigurationRevision;
use App\Application\Targets\TargetConnectorAdapter;
use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorResult;
use App\Application\Targets\TargetEndpointPreflight;
use App\Application\Targets\TargetEnrollmentPreflight;
use App\Application\Targets\TargetPreflightResult;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Http\Api\ApiHttpTransport;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\OutboundTargetPolicy;
use App\Infrastructure\Http\UnsafeOutboundTarget;
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

    public function register(array $input): Target
    {
        try {
            $base = $this->canonical((string) $input['api_base_url']);
            $spec = $this->nullableUrl($input['api_spec_url'] ?? null);
            $probe = $this->probe($input['api_probe_path'] ?? null);
            $key = (string) $input['api_key'];

            return DB::transaction(function () use ($input, $base, $spec, $probe, $key): Target {
                $target = Target::query()->create([
                    'target_id' => (string) $input['target_id'],
                    'display_name' => (string) $input['display_name'],
                    'ai_guidance' => $input['ai_guidance'] ?? null,
                    'connector_type' => $this->type(),
                    'connection_state' => TargetConnectionState::Disconnected,
                ]);
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
                    'encrypted_payload' => $this->vault->seal($target, $config, $key),
                ]);
                $this->activity->recordRequired(CorrelationId::current(), 'arvan-target-register', 'success', $target);

                return $target;
            });
        } catch (UniqueConstraintViolationException $exception) {
            throw new TargetConnectorFailure(__('Target ID is already in use.'), 'target_id', 'invalid_input', []);
        } catch (UnsafeOutboundTarget|OutboundRequestException $exception) {
            throw new TargetConnectorFailure(__('ArvanCloud endpoint could not be safely verified.'), 'api_base_url', 'unsafe_target', []);
        } catch (InvalidArgumentException|RuntimeException $exception) {
            throw new TargetConnectorFailure(__('ArvanCloud endpoint, probe or API credential is invalid.'), 'api_base_url', 'invalid_input', []);
        }
    }

    public function registrationStatus(): string
    {
        return __('ArvanCloud API Target saved with an encrypted key. An authenticated GET health probe has not yet been verified.');
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
            $spec = $this->nullableUrl($input['api_spec_url'] ?? null);
            $probe = $this->probe($input['api_probe_path'] ?? null);

            DB::transaction(function () use ($target, $input, $base, $spec, $probe): void {
                $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->firstOrFail();
                $config = $this->config($locked);
                $credential = $this->credential($locked);
                if (! hash_equals($this->configurationRevision($locked), (string) $input['configuration_revision'])) {
                    throw new InvalidArgumentException('Target configuration changed. Reload to avoid overwriting current credentials.');
                }
                $changedBase = ! hash_equals($config->base_url, $base);
                $newKey = (string) ($input['api_key'] ?? '');
                if ($changedBase && $newKey === '') {
                    throw new InvalidArgumentException('A new key is required when changing the API endpoint.');
                }
                $config->forceFill(['base_url' => $base, 'spec_url' => $spec, 'probe_path' => $probe])->save();
                if ($newKey !== '') {
                    $sealed = $this->vault->seal($locked, $config, $newKey);
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
                if ($changedBase || $newKey !== '') {
                    $locked->forceFill(['connection_state' => TargetConnectionState::Disconnected, 'connected_at' => null])->save();
                }
                $this->activity->recordRequired(CorrelationId::current(), 'arvan-target-configure', 'success', $locked);
            });

            return new TargetConnectorResult(statusMessage: __('ArvanCloud API settings saved. Re-test the credential if the endpoint or key changed.'));
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
            TargetCredential::query()->where('target_record_id', $target->getKey())
                ->where('connector_type', $this->type())
                ->where('purpose', ArvanApiTargetVault::PURPOSE)->delete();
            $target->forceFill(['connection_state' => TargetConnectionState::Disconnected, 'connected_at' => null])->save();
            $this->activity->recordRequired(CorrelationId::current(), 'arvan-target-disconnect', 'success', $target);
        });

        return new TargetConnectorResult(statusMessage: __('Gateway deleted its local ArvanCloud credential. Revoke the Machine User API key in ArvanCloud separately if required.'));
    }

    public function test(Target $target): TargetConnectorResult
    {
        $config = $this->config($target);
        if ($config->probe_path === null) {
            throw new TargetConnectorFailure(
                __('Configure one known read-only GET probe path before declaring this account verified.'),
                'api_probe_path', 'probe_not_configured',
            );
        }
        try {
            $key = $this->vault->open($target, $config, $this->credential($target)
                ?? throw new RuntimeException('ArvanCloud credential was disconnected.'));
            $response = $this->transport->request(
                $config->base_url, 'GET', $config->probe_path, [],
                null, ['Authorization' => 'Apikey '.$key],
            );
            if ($response->status < 200 || $response->status >= 300) {
                throw new TargetConnectorFailure(
                    __('ArvanCloud returned HTTP :status on the configured GET probe.', ['status' => $response->status]),
                    null, 'upstream_http_error', ['http_status' => $response->status],
                );
            }
            $target->forceFill([
                'connection_state' => TargetConnectionState::Connected,
                'connected_at' => now(),
                'last_tested_at' => now(),
                'last_success_at' => now(),
                'last_error_code' => null,
            ])->save();

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
