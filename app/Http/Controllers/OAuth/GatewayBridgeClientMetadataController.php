<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Infrastructure\OAuth\GatewayBridgeClientIdentity;
use Illuminate\Http\JsonResponse;

final class GatewayBridgeClientMetadataController extends Controller
{
    public function __invoke(GatewayBridgeClientIdentity $identity): JsonResponse
    {
        return response()->json($identity->metadata(), 200, [
            'Cache-Control' => 'public, max-age=300',
        ], JSON_UNESCAPED_SLASHES);
    }
}
