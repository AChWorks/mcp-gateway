<?php

namespace App\Http\Controllers\OAuth;

use App\Infrastructure\OAuth\DcrClientRegistration;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use InvalidArgumentException;
use RuntimeException;

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
                && (int) $declaredLength > 8192)
            || strlen($request->getContent()) > 8192) {
            return $this->error('invalid_client_metadata', 'Registration requires bounded JSON.', 400);
        }

        $data = json_decode($request->getContent(), true);
        if (! is_array($data) || array_is_list($data)) {
            return $this->error('invalid_client_metadata', 'Registration metadata must be a JSON object.', 400);
        }

        try {
            return response()->json($this->registration->register($data), 201)
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        } catch (InvalidArgumentException) {
            return $this->error('invalid_client_metadata', 'Unsupported OAuth client registration metadata.', 400);
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
