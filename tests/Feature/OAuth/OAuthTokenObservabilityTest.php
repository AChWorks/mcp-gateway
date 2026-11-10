<?php

namespace Tests\Feature\OAuth;

use App\Http\Middleware\ObserveOAuthTokenRequest;
use App\Infrastructure\OAuth\OAuthClientAuthDiagnostic;
use App\Support\CorrelationId;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Tests\TestCase;

final class OAuthTokenObservabilityTest extends TestCase
{
    use RefreshDatabase;

    public function test_successful_streamed_exchange_logs_refresh_token_issued_true_from_request_state(): void
    {
        $request = $this->tokenRequest('authorization_code');
        $request->attributes->set('oauth_refresh_token_issued', true);
        Log::spy();

        $response = app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => new StreamedResponse(static function (): void {}),
        );

        self::assertSame(200, $response->getStatusCode());
        $this->assertDiagnostic($request, 'oauth-token-authorization-code', true, false);
    }

    public function test_successful_streamed_exchange_logs_refresh_token_issued_false_from_request_state(): void
    {
        $request = $this->tokenRequest('refresh_token');
        $request->attributes->set('oauth_refresh_token_issued', false);
        Log::spy();

        $response = app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => new StreamedResponse(static function (): void {}),
        );

        self::assertSame(200, $response->getStatusCode());
        $this->assertDiagnostic($request, 'oauth-token-refresh', false, false);
    }

    public function test_recovered_exchange_preserves_refresh_issuance_diagnostic(): void
    {
        $request = $this->tokenRequest('refresh_token');
        $request->attributes->set('oauth_token_recovered', true);
        $request->attributes->set('oauth_refresh_token_issued', true);
        Log::spy();

        $response = app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => new StreamedResponse(static function (): void {}),
        );

        self::assertSame(200, $response->getStatusCode());
        $this->assertDiagnostic($request, 'oauth-token-refresh-recovery', true, true);
    }

    public function test_failed_exchange_does_not_claim_refresh_token_issuance(): void
    {
        $request = $this->tokenRequest('refresh_token');
        $request->attributes->set('oauth_refresh_token_issued', true);
        $request->attributes->set('oauth_token_error_code', 'invalid_grant');
        Log::spy();

        $response = app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => new StreamedResponse(static function (): void {}, 400),
        );

        self::assertSame(400, $response->getStatusCode());
        $this->assertDiagnostic($request, 'oauth-token-refresh', null, false, 'failure', 'invalid_grant');
    }

    public function test_invalid_client_failure_is_available_in_existing_activity_and_logs_without_raw_claims(): void
    {
        $request = $this->tokenRequest('refresh_token');
        $request->attributes->set('oauth_token_error_code', 'invalid_client');
        $request->attributes->set(OAuthClientAuthDiagnostic::ATTRIBUTE, [
            'oauth_failure_stage' => 'jwt_signature',
            'oauth_failure_reason' => 'assertion_signature_invalid',
            'exception_class' => SignatureInvalidException::class,
            'untrusted_claim' => 'should-never-be-persisted',
        ]);
        Log::spy();

        $response = app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => new StreamedResponse(static function (): void {}, 401),
        );

        self::assertSame(401, $response->getStatusCode());
        $event = DB::table('activity_events')
            ->where('correlation_id', $request->attributes->get(CorrelationId::ATTRIBUTE))
            ->first();
        self::assertNotNull($event);
        self::assertSame('invalid_client', $event->error_code);
        $details = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('jwt_signature', $details['oauth_failure_stage']);
        self::assertSame('assertion_signature_invalid', $details['oauth_failure_reason']);
        self::assertSame(SignatureInvalidException::class, $details['exception_class']);
        self::assertStringNotContainsString('should-never-be-persisted', (string) $event->diagnostic_context);

        Log::shouldHaveReceived('info')->once()->with(
            'OAuth token exchange completed.',
            \Mockery::on(static fn (array $context): bool => ($context['oauth_failure_stage'] ?? null) === 'jwt_signature'
                && ($context['oauth_failure_reason'] ?? null) === 'assertion_signature_invalid'
                && ! str_contains(json_encode($context, JSON_THROW_ON_ERROR), 'should-never-be-persisted')),
        );
    }

    public function test_revocation_failure_uses_the_same_client_authentication_diagnostic_path(): void
    {
        $request = Request::create('/oauth/revoke', 'POST', []);
        $request->attributes->set(CorrelationId::ATTRIBUTE, (string) Str::uuid());
        $request->attributes->set('oauth_token_error_code', 'invalid_client');
        $request->attributes->set(OAuthClientAuthDiagnostic::ATTRIBUTE, [
            'oauth_failure_stage' => 'dcr_client_auth',
            'oauth_failure_reason' => 'secret_mismatch_or_client_unavailable',
        ]);
        $this->app->instance('request', $request);
        Log::spy();

        app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => new StreamedResponse(static function (): void {}, 401),
        );

        $event = DB::table('activity_events')
            ->where('correlation_id', $request->attributes->get(CorrelationId::ATTRIBUTE))
            ->first();
        self::assertNotNull($event);
        self::assertSame('oauth-token-revoke', $event->operation);
        self::assertSame('invalid_client', $event->error_code);
        $details = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('secret_mismatch_or_client_unavailable', $details['oauth_failure_reason']);
        Log::shouldHaveReceived('info')->once()->with(
            'OAuth token revocation completed.',
            \Mockery::on(static fn (array $context): bool => ($context['operation'] ?? null) === 'oauth-token-revoke'
                && ($context['oauth_failure_stage'] ?? null) === 'dcr_client_auth'),
        );
    }

    public function test_unhandled_credential_operation_logs_exception_class_not_exception_message(): void
    {
        $request = $this->tokenRequest('refresh_token');
        Log::spy();
        $secret = 'SECRET_SENTINEL_NOT_FOR_DIAGNOSTICS';

        $this->expectExceptionMessage($secret);
        try {
            app(ObserveOAuthTokenRequest::class)->handle(
                $request,
                static fn (): StreamedResponse => throw new \RuntimeException($secret),
            );
        } finally {
            $event = DB::table('activity_events')
                ->where('correlation_id', $request->attributes->get(CorrelationId::ATTRIBUTE))
                ->first();
            self::assertNotNull($event);
            self::assertSame('server_failure', $event->error_code);
            self::assertStringNotContainsString($secret, (string) $event->diagnostic_context);
            $details = json_decode((string) $event->diagnostic_context, true, flags: JSON_THROW_ON_ERROR);
            self::assertSame(\RuntimeException::class, $details['exception_class']);
            self::assertSame('request_execution', $details['oauth_failure_stage']);
        }
    }

    public function test_diagnostic_logging_failure_does_not_change_token_response(): void
    {
        $request = $this->tokenRequest('authorization_code');
        $request->attributes->set('oauth_refresh_token_issued', true);
        Log::shouldReceive('info')
            ->once()
            ->andThrow(new \RuntimeException('diagnostic sink unavailable'));

        $expected = new StreamedResponse(static function (): void {}, 200, ['X-Test' => 'preserved']);
        $response = app(ObserveOAuthTokenRequest::class)->handle(
            $request,
            static fn (): StreamedResponse => $expected,
        );

        self::assertSame($expected, $response);
        self::assertSame('preserved', $response->headers->get('X-Test'));
        self::assertSame(200, $response->getStatusCode());
    }

    private function tokenRequest(string $grantType): Request
    {
        $request = Request::create('/oauth/token', 'POST', ['grant_type' => $grantType]);
        $request->attributes->set(CorrelationId::ATTRIBUTE, (string) Str::uuid());
        $this->app->instance('request', $request);

        return $request;
    }

    private function assertDiagnostic(
        Request $request,
        string $operation,
        ?bool $refreshTokenIssued,
        bool $recovered,
        string $outcome = 'success',
        ?string $errorCode = null,
    ): void {
        $correlationId = (string) $request->attributes->get(CorrelationId::ATTRIBUTE);

        Log::shouldHaveReceived('info')
            ->with(
                'OAuth token exchange completed.',
                \Mockery::on(static fn (array $context): bool => ($context['correlation_id'] ?? null) === $correlationId
                    && ($context['operation'] ?? null) === $operation
                    && ($context['outcome'] ?? null) === $outcome
                    && ($context['error_code'] ?? null) === $errorCode
                    && ($context['refresh_token_issued'] ?? null) === $refreshTokenIssued
                    && ($context['recovered'] ?? null) === $recovered
                ),
            )
            ->once();
    }
}
