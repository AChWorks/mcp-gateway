<?php

use App\Http\Controllers\OAuth\AuthorizationServerMetadataController;
use App\Http\Controllers\OAuth\ProtectedResourceMetadataController;
use App\Http\Controllers\OAuth\RevocationController;
use App\Http\Controllers\OAuth\TokenController;
use App\Http\Middleware\RequireMcpAccessToken;
use App\Infrastructure\Mcp\BootstrapMcpEndpoint;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use Illuminate\Support\Facades\Route;

Route::get('/.well-known/oauth-protected-resource/mcp', ProtectedResourceMetadataController::class);
Route::get('/.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class);

Route::post('/oauth/token', TokenController::class)->middleware('throttle:oauth-token');
Route::post('/oauth/revoke', RevocationController::class)->middleware('throttle:oauth-token');

Route::match(['POST', 'DELETE', 'OPTIONS'], '/mcp', [GatewayMcpEndpoint::class, 'handle'])
    ->middleware(['throttle:mcp-edge', RequireMcpAccessToken::class, 'throttle:mcp']);

Route::match(
    ['POST', 'DELETE', 'OPTIONS'],
    '/_internal/mcp-bootstrap',
    [BootstrapMcpEndpoint::class, 'handle'],
);
