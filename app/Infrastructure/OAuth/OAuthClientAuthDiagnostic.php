<?php

namespace App\Infrastructure\OAuth;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

/**
 * Server-side evidence for a rejected OAuth client authentication attempt.
 * Never attach a JWT, client secret, token, claims or input-derived message.
 * The wire response deliberately remains the same generic invalid_client.
 */
final class OAuthClientAuthDiagnostic
{
    public const ATTRIBUTE = 'oauth_client_auth_diagnostic';

    public static function invalidClient(
        ServerRequestInterface $request,
        string $stage,
        string $reason,
        ?Throwable $cause = null,
    ): OAuthServerException {
        self::remember($stage, $reason, $cause);

        return OAuthServerException::invalidClient($request);
    }

    public static function remember(string $stage, string $reason, ?Throwable $cause = null): void
    {
        try {
            if (! app()->bound('request')) {
                return;
            }

            $request = app('request');
            // Only trusted authentication branches provide these identifiers.
            // The observed remote HTTP status is useful when client metadata
            // returns 404/503; never record its response body or URL query.
            $details = [
                'oauth_failure_stage' => $stage,
                'oauth_failure_reason' => $reason,
                ...($cause !== null ? ['exception_class' => $cause::class] : []),
            ];
            if ($cause instanceof OAuthClientMetadataUnavailable && $cause->upstreamStatus !== null) {
                $details['remote_http_status'] = $cause->upstreamStatus;
            }
            $request->attributes->set(self::ATTRIBUTE, $details);
        } catch (Throwable) {
            // Diagnostics must never change the authentication outcome.
        }
    }
}
