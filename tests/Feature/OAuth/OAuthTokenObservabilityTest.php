<?php

namespace Tests\Feature\OAuth;

use App\Http\Middleware\ObserveOAuthTokenRequest;
use App\Support\CorrelationId;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
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
