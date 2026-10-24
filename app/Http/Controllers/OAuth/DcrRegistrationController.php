<?php

namespace App\Http\Controllers\OAuth;

use App\Infrastructure\OAuth\DcrClientRegistration;
use App\Infrastructure\OAuth\DcrRegistrationRateLimited;
use App\Support\CorrelationId;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

final readonly class DcrRegistrationController
{
    public function __construct(private DcrClientRegistration $registration) {}

    public function __invoke(Request $request): JsonResponse
    {
        if (config('oauth.dcr.registration_enabled') !== true) {
            return $this->error('invalid_client_metadata', 'Registration is not available.', 404);
        }

        $contentType = strtolower(trim(explode(';', (string) $request->header('Content-Type'), 2)[0]));
        $declaredLength = $request->header('Content-Length');
        if ($contentType !== 'application/json'
            || (is_string($declaredLength) && ctype_digit($declaredLength)
                && (int) $declaredLength > 8192)) {
            return $this->error('invalid_client_metadata', 'Registration requires bounded JSON.', 400);
        }

        // Limit actual bytes read, not merely a reported Content-Length. A
        // chunked client may omit that header entirely.
        $stream = $request->getContent(true);
        $body = is_resource($stream) ? stream_get_contents($stream, 8193) : false;
        if (! is_string($body) || strlen($body) > 8192) {
            return $this->error('invalid_client_metadata', 'Registration requires bounded JSON.', 400);
        }

        $data = json_decode($body, true);
        if (! is_array($data) || array_is_list($data)) {
            return $this->error('invalid_client_metadata', 'Registration metadata must be a JSON object.', 400);
        }

        try {
            $registered = $this->registration->register($data);

            try {
                Log::info('OAuth DCR client registration completed.', [
                    'correlation_id' => CorrelationId::current(),
                    'client_id_hash' => hash('sha256', (string) $registered['client_id']),
                    'auth_strategy' => 'dcr_client_secret_post',
                ]);
            } catch (Throwable) {
                // Diagnostics must never reveal credentials or alter registration.
            }

            return response()->json($registered, 201)
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        } catch (InvalidArgumentException) {
            return $this->error('invalid_client_metadata', 'Unsupported OAuth client registration metadata.', 400);
        } catch (DcrRegistrationRateLimited $exception) {
            return $this->error('slow_down', 'Registration rate limit exceeded.', 429)
                ->header('Retry-After', (string) $exception->retryAfterSeconds);
        } catch (RuntimeException) {
            return $this->error('temporarily_unavailable', 'Registration capacity is temporarily unavailable.', 503);
        }
    }

    private function error(string $code, string $description, int $status): JsonResponse
    {
        return response()->json(['error' => $code, 'error_description' => $description], $status)
            ->header('Cache-Control', 'no-store')
            ->header('Pragma', 'no-cache');
    }
}
