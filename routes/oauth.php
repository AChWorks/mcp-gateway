<?php

use App\Http\Controllers\OAuth\AuthorizationController;
use App\Http\Controllers\OAuth\GatewayBridgeClientJwksController;
use App\Http\Controllers\OAuth\GatewayBridgeClientMetadataController;
use App\Http\Controllers\OAuth\SiteOAuthCallbackController;
use App\Http\Middleware\EnsureLocalUserAccessEnabled;
use Illuminate\Support\Facades\Route;

Route::get('/oauth/client.json', GatewayBridgeClientMetadataController::class)
    ->name('bridge.client.metadata');
Route::get('/oauth/jwks.json', GatewayBridgeClientJwksController::class)
    ->name('bridge.client.jwks');
Route::get('/oauth/sites/callback', SiteOAuthCallbackController::class)
    ->middleware('throttle:oauth-browser')
    ->name('bridge.site.callback');

Route::get('/oauth/authorize', [AuthorizationController::class, 'show'])
    ->middleware([EnsureLocalUserAccessEnabled::class, 'throttle:oauth-browser']);
Route::post('/oauth/authorize', [AuthorizationController::class, 'complete'])
    ->middleware([EnsureLocalUserAccessEnabled::class, 'throttle:oauth-browser']);
