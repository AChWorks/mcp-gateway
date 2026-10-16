<?php

use App\Http\Controllers\Mcp\SshWholeFileController;
use App\Http\Controllers\OAuth\AuthorizationServerMetadataController;
use App\Http\Controllers\OAuth\ProtectedResourceMetadataController;
use App\Http\Controllers\OAuth\RevocationController;
use App\Http\Controllers\OAuth\TokenController;
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

// Direct SSH whole-file binary edge shares live OAuth and the exact
// principal/client/Target operation grants of the MCP endpoint.
// Fresh installer enables it explicitly; existing installs with an absent
// SSH_FILE_TRANSFER_ENABLED key remain OFF, and explicit false disables it.
// This does not provide native ChatGPT attachment handoff (#147).
Route::post('/mcp/file-transfer/ssh/{targetId}/upload', [SshWholeFileController::class, 'upload'])
    ->middleware([EnsureCorrelationId::class, 'throttle:mcp-edge', RequireMcpAccessToken::class, 'throttle:mcp']);
Route::post('/mcp/file-transfer/ssh/{targetId}/download', [SshWholeFileController::class, 'download'])
    ->middleware([EnsureCorrelationId::class, 'throttle:mcp-edge', RequireMcpAccessToken::class, 'throttle:mcp']);

Route::match(
    ['POST', 'DELETE', 'OPTIONS'],
    '/_internal/mcp-bootstrap',
    [BootstrapMcpEndpoint::class, 'handle'],
);
