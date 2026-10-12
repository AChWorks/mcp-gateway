<?php

use App\Http\Controllers\OAuth\AuthorizationServerMetadataController;
use App\Http\Controllers\OAuth\ProtectedResourceMetadataController;
use App\Http\Controllers\OAuth\RevocationController;
use App\Http\Controllers\OAuth\TokenController;
use App\Http\Controllers\Mcp\SshWholeFileController;
use App\Http\Middleware\EnsureCorrelationId;
use App\Http\Middleware\ObserveOAuthTokenRequest;
use App\Http\Middleware\RequireMcpAccessToken;
use App\Infrastructure\Mcp\BootstrapMcpEndpoint;
use App\Infrastructure\Mcp\GatewayMcpEndpoint;
use Illuminate\Support\Facades\Route;

Route::get('/.well-known/oauth-protected-resource/mcp', ProtectedResourceMetadataController::class);
Route::get('/.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class);

Route::post('/oauth/token', TokenController::class)->middleware([EnsureCorrelationId::class, ObserveOAuthTokenRequest::class, 'throttle:oauth-token']);
Route::post('/oauth/revoke', RevocationController::class)->middleware('throttle:oauth-token');

Route::match(['POST', 'DELETE', 'OPTIONS'], '/mcp', [GatewayMcpEndpoint::class, 'handle'])
    ->middleware([EnsureCorrelationId::class, 'throttle:mcp-edge', RequireMcpAccessToken::class, 'throttle:mcp']);

// Draft #147: optional binary sidecar, protected by the SAME live OAuth and
// principal/client/Target operation grants as the normal MCP endpoint.
// OFF BY DEFAULT until a separately authorized protocol/security decision.
Route::post('/mcp/file-transfer/ssh/{targetId}/upload', [SshWholeFileController::class, 'upload'])
    ->middleware([EnsureCorrelationId::class, 'throttle:mcp-edge', RequireMcpAccessToken::class, 'throttle:mcp']);
Route::post('/mcp/file-transfer/ssh/{targetId}/download', [SshWholeFileController::class, 'download'])
    ->middleware([EnsureCorrelationId::class, 'throttle:mcp-edge', RequireMcpAccessToken::class, 'throttle:mcp']);

Route::match(
    ['POST', 'DELETE', 'OPTIONS'],
    '/_internal/mcp-bootstrap',
    [BootstrapMcpEndpoint::class, 'handle'],
);
