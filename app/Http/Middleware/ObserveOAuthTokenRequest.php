<?php

namespace App\Http\Middleware;

use App\Infrastructure\Activity\ActivityRecorder;
use App\Support\CorrelationId;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final readonly class ObserveOAuthTokenRequest
{
    public function __construct(private ActivityRecorder $activity) {}

    public function handle(Request $request, Closure $next): Response
    {
        $operation = $this->operation($request->input('grant_type'));

        try {
            $response = $next($request);
        } catch (Throwable $throwable) {
            $this->activity->record(
                CorrelationId::current(),
                $operation,
                'failure',
                null,
                'server_failure',
            );

            throw $throwable;
        }

        if ($request->attributes->get('oauth_token_recovered') === true) {
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

        $this->activity->record(
            CorrelationId::current(),
            $operation,
            $response->isSuccessful() ? 'success' : 'failure',
            null,
            $errorCode,
        );

        return $response;
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
