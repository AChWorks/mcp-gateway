<?php

namespace App\Http\Middleware;

use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\OAuth\OAuthClientAuthDiagnostic;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final readonly class ObserveOAuthTokenRequest
{
    public function __construct(private ActivityRecorder $activity) {}

    public function handle(Request $request, Closure $next): Response
    {
        $isRevocation = $request->is('oauth/revoke');
        $operation = $isRevocation ? 'oauth-token-revoke' : $this->operation($request->input('grant_type'));

        try {
            $response = $next($request);
        } catch (Throwable $throwable) {
            $request->attributes->set('gateway_error_logged', true);
            $observed = $request->attributes->get(OAuthClientAuthDiagnostic::ATTRIBUTE);
            $details = is_array($observed) ? OperationDiagnostics::safeContext($observed) : [];
            $this->activity->record(
                CorrelationId::current(),
                $operation,
                'failure',
                null,
                'server_failure',
                [
                    ...$details,
                    'exception_class' => $throwable::class,
                    'oauth_failure_stage' => $details['oauth_failure_stage'] ?? 'request_execution',
                    'oauth_failure_reason' => $details['oauth_failure_reason'] ?? 'unhandled_exception',
                ],
            );

            throw $throwable;
        }

        $recovered = $request->attributes->get('oauth_token_recovered') === true;
        if ($recovered) {
            $operation = 'oauth-token-refresh-recovery';
        }

        $errorCode = null;
        if ($response->getStatusCode() === 429) {
            $errorCode = 'rate_limited';
        } else {
            $reported = $request->attributes->get('oauth_token_error_code');
            if (is_string($reported) && $reported !== '') {
                $errorCode = $reported;
            } elseif (! $response->isSuccessful()) {
                $errorCode = 'request_failed';
            }
        }

        $outcome = $response->isSuccessful() ? 'success' : 'failure';
        $correlationId = CorrelationId::current();
        // The authenticator, not the public OAuth error code, owns the
        // observed failure provenance. An unexpected profile lookup failure
        // may already have been rendered as a 500 by the framework pipeline.
        $observed = $request->attributes->get(OAuthClientAuthDiagnostic::ATTRIBUTE);
        $authenticationEvidence = ! $response->isSuccessful() && is_array($observed)
            ? OperationDiagnostics::safeContext($observed) : [];
        $details = [
            ...$authenticationEvidence,
            ...($response->getStatusCode() === 429 ? [
                'failure_origin' => 'gateway_admission',
                'request_not_sent' => true,
            ] : []),
        ];

        // ActivityRecorder owns failure logging. Do not emit a second info
        // record here or let the outer HTTP middleware duplicate a 5xx warning.
        if ($response->getStatusCode() >= 500) {
            $request->attributes->set('gateway_error_logged', true);
        }
        $this->activity->record(
            $correlationId,
            $operation,
            $outcome,
            null,
            $errorCode,
            $details,
        );

        if (! $response->isSuccessful()) {
            return $response;
        }

        try {
            Log::info($isRevocation ? 'OAuth token revocation completed.' : 'OAuth token exchange completed.', [
                'correlation_id' => $correlationId,
                'operation' => $operation,
                'outcome' => $outcome,
                'error_code' => $errorCode,
                'status' => $response->getStatusCode(),
                'requested_scopes' => $this->requestedScopes($request),
                'refresh_token_issued' => $this->refreshTokenIssued($request, $response),
                'recovered' => $recovered,
                ...$authenticationEvidence,
            ]);
        } catch (Throwable) {
            // Diagnostics must never change the token exchange outcome.
        }

        return $response;
    }

    /** @return list<string> */
    private function requestedScopes(Request $request): array
    {
        $scope = $request->input('scope');
        if (! is_string($scope) || trim($scope) === '') {
            return [];
        }

        $requested = preg_split('/\\s+/', trim($scope), -1, PREG_SPLIT_NO_EMPTY);
        if (! is_array($requested)) {
            return [];
        }

        $supported = array_values(array_map('strval', (array) config('oauth.scopes')));

        return array_values(array_unique(array_intersect($requested, $supported)));
    }

    private function refreshTokenIssued(Request $request, Response $response): ?bool
    {
        if (! $response->isSuccessful()) {
            return null;
        }

        $issued = $request->attributes->get('oauth_refresh_token_issued');

        return is_bool($issued) ? $issued : null;
    }

    private function operation(mixed $grantType): string
    {
        return match ($grantType) {
            'authorization_code' => 'oauth-token-authorization-code',
            'refresh_token' => 'oauth-token-refresh',
            default => 'oauth-token-unknown',
        };
    }
}
