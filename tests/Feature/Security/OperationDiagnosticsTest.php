<?php

namespace Tests\Feature\Security;

use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Support\OperationDiagnostics;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Tests\TestCase;

final class OperationDiagnosticsTest extends TestCase
{
    use RefreshDatabase;

    public function test_safe_diagnostics_log_only_whitelisted_fields_and_a_lookup_reference(): void
    {
        Log::spy();
        $target = $this->target();
        $reference = OperationDiagnostics::failure('wordpress-disconnect', 'network_failure', $target, [
            'failure_stage' => 'dns_timeout',
            'http_status' => 503,
            'pre_dispatch' => true,
            'failure_origin' => 'gateway_response',
            'phase' => 'content_length',
            'limit_bytes' => 1024,
            'observed_bytes' => 2048,
            'retry_safe' => false,
            'invalid_origin' => 'PRIVATE_ORIGIN_MUST_NOT_LOG',
            'token' => 'VERY_SECRET_TOKEN_MUST_NOT_LOG',
            'url' => 'https://site.example.test/secret/path',
            'raw_exception' => 'Bearer PRIVATE_JWT',
            'error_body' => 'PRIVATE_REMOTE_RESPONSE',
        ]);

        self::assertTrue(Str::isUuid($reference));
        Log::shouldHaveReceived('warning')->once()
            ->withArgs(static function (string $message, array $context) use ($reference, $target): bool {
                $json = json_encode($context, JSON_THROW_ON_ERROR);

                return $message === 'Gateway operation failure.'
                    && $context['correlation_id'] === $reference
                    && $context['operation'] === 'wordpress-disconnect'
                    && $context['error_code'] === 'network_failure'
                    && $context['failure_stage'] === 'dns_timeout'
                    && $context['failure_origin'] === 'gateway_response'
                    && $context['response_phase'] === 'content_length'
                    && $context['limit_bytes'] === 1024
                    && $context['observed_bytes'] === 2048
                    && $context['retry_safe'] === false
                    && $context['remote_http_status'] === 503
                    && $context['request_not_sent'] === true
                    && $context['target_id'] === $target->target_id
                    && ! str_contains($json, 'VERY_SECRET_TOKEN_MUST_NOT_LOG')
                    && ! str_contains($json, 'PRIVATE_JWT')
                    && ! str_contains($json, 'site.example.test')
                    && ! str_contains($json, 'PRIVATE_REMOTE_RESPONSE')
                    && ! str_contains($json, 'PRIVATE_ORIGIN_MUST_NOT_LOG');
            });

        self::assertStringContainsString('DNS', OperationDiagnostics::nextStep('network_failure'));
        self::assertStringContainsString('revocation', OperationDiagnostics::summary('revocation_pending'));
    }

    public function test_mcp_activity_failure_uses_same_correlation_id_in_structured_log(): void
    {
        Log::spy();
        $reference = (string) Str::uuid();
        $target = $this->target();
        app(ActivityRecorder::class)->record(
            $reference, 'ssh-file-write', 'unknown', $target, 'outcome_unknown',
        );

        $this->assertDatabaseHas('activity_events', [
            'correlation_id' => $reference,
            'operation' => 'ssh-file-write',
            'outcome' => 'unknown',
            'error_code' => 'outcome_unknown',
        ]);
        Log::shouldHaveReceived('warning')->once()
            ->withArgs(static fn (string $message, array $context): bool => $message === 'Gateway operation failure.'
                && $context['correlation_id'] === $reference
                && $context['operation'] === 'ssh-file-write'
                && $context['retry_safe'] === false);
    }

    public function test_all_http_routes_have_a_server_lookup_reference_without_exposing_it_in_bodies(): void
    {
        $login = $this->get('/admin/login')->assertOk();
        $id = $login->headers->get('X-Correlation-ID');
        self::assertTrue(is_string($id) && Str::isUuid($id));
        self::assertStringNotContainsString($id, $login->getContent());

        $missing = $this->get('/this-route-does-not-exist')->assertNotFound();
        self::assertTrue(Str::isUuid((string) $missing->headers->get('X-Correlation-ID')));

        $mcp = $this->post('/mcp', ['jsonrpc' => '2.0', 'method' => 'ping', 'id' => 1])
            ->assertUnauthorized();
        self::assertTrue(Str::isUuid((string) $mcp->headers->get('X-Correlation-ID')));
    }

    private function target(): Target
    {
        return Target::query()->create([
            'target_id' => 'diagnostic-target',
            'display_name' => 'Diagnostic target',
            'connector_type' => 'ssh_direct',
        ]);
    }
}
