<?php

use App\Http\Controllers\Admin\AuthenticatedSessionController;
use App\Http\Controllers\OAuth\AuthorizationController;
use App\Http\Controllers\OAuth\GatewayBridgeClientJwksController;
use App\Http\Controllers\OAuth\GatewayBridgeClientMetadataController;
use App\Http\Controllers\OAuth\SiteOAuthCallbackController;
use Illuminate\Support\Facades\Route;

Route::view('/', 'welcome');

Route::get('/admin/login', static fn () => view('admin.login'))
    ->middleware('guest')
    ->name('login');
Route::post('/admin/login', [AuthenticatedSessionController::class, 'store'])
    ->middleware(['guest', 'throttle:admin-login'])
    ->name('admin.login.store');

Route::middleware('auth')->prefix('admin')->group(function (): void {
    Route::view('/', 'admin.dashboard')->name('admin.dashboard');
    Route::view('/connection', 'admin.connection')->name('admin.connection');
    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])
        ->name('admin.logout');
});

Route::get('/oauth/client.json', GatewayBridgeClientMetadataController::class)
    ->name('bridge.client.metadata');
Route::get('/oauth/jwks.json', GatewayBridgeClientJwksController::class)
    ->name('bridge.client.jwks');
Route::get('/oauth/sites/callback', SiteOAuthCallbackController::class)
    ->middleware('throttle:oauth-browser')
    ->name('bridge.site.callback');

Route::get('/oauth/authorize', [AuthorizationController::class, 'show'])
    ->middleware('throttle:oauth-browser');
Route::post('/oauth/authorize', [AuthorizationController::class, 'complete'])
    ->middleware('throttle:oauth-browser');
