<?php

use App\Http\Controllers\OAuth\AuthorizationController;
use App\Http\Controllers\OAuth\GatewayBridgeClientJwksController;
use App\Http\Controllers\OAuth\GatewayBridgeClientMetadataController;
use App\Http\Controllers\OAuth\TargetOAuthCallbackController;
use App\Http\Middleware\EnsureLocalUserAccessEnabled;
use Illuminate\Support\Facades\Route;

Route::get('/oauth/client.json', GatewayBridgeClientMetadataController::class)
    ->name('bridge.client.metadata');
Route::get('/oauth/jwks.json', GatewayBridgeClientJwksController::class)
    ->name('bridge.client.jwks');
// The breaking Target migration requires fresh WordPress OAuth authorization.
Route::get('/oauth/targets/callback', TargetOAuthCallbackController::class)
    ->middleware('throttle:oauth-browser')
    ->name('bridge.target.callback');

Route::get('/oauth/authorize', [AuthorizationController::class, 'show'])
    ->middleware([EnsureLocalUserAccessEnabled::class, 'throttle:oauth-browser']);
Route::post('/oauth/authorize', [AuthorizationController::class, 'complete'])
    ->middleware([EnsureLocalUserAccessEnabled::class, 'throttle:oauth-browser']);
