<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use Illuminate\Http\JsonResponse;
use RuntimeException;

final class GatewayBridgeClientJwksController extends Controller
{
    public function __invoke(GatewayBridgeClientIdentity $identity): JsonResponse
    {
        try {
            $jwks = $identity->jwks();
        } catch (RuntimeException $exception) {
            return response()->json(['error' => 'signing_keys_unavailable'], 503, [
                'Cache-Control' => 'no-store',
            ]);
        }

        return response()->json($jwks, 200, [
            'Cache-Control' => 'public, max-age=300',
        ], JSON_UNESCAPED_SLASHES);
    }
}
