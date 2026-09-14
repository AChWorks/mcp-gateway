<?php

namespace App\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;

final class ProtectedResourceMetadataController
{
    public function __invoke(): JsonResponse
    {
        return response()->json([
            'resource' => (string) config('oauth.resource'),
            'authorization_servers' => [(string) config('oauth.issuer')],
            'scopes_supported' => array_values((array) config('oauth.scopes')),
            'bearer_methods_supported' => ['header'],
        ])->header('Cache-Control', 'public, max-age=300');
    }
}
