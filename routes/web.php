<?php

use App\Http\Controllers\Admin\AuthenticatedSessionController;
use App\Http\Controllers\OAuth\AuthorizationController;
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
    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])
        ->name('admin.logout');
});

Route::get('/oauth/authorize', [AuthorizationController::class, 'show'])
    ->middleware('throttle:oauth-browser');
Route::post('/oauth/authorize', [AuthorizationController::class, 'complete'])
    ->middleware('throttle:oauth-browser');
