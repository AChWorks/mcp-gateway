<?php

use App\Http\Controllers\Admin\ActivityController;
use App\Http\Controllers\Admin\AuthenticatedSessionController;
use App\Http\Controllers\Admin\DashboardController;
use App\Http\Controllers\Admin\OAuthClientAuthorizationsController;
use App\Http\Controllers\Admin\SiteCheckOperationController;
use App\Http\Controllers\Admin\SiteConnectionController;
use App\Http\Controllers\Admin\SiteController;
use App\Http\Controllers\Admin\TargetController;
use App\Http\Controllers\Admin\TargetGroupController;
use App\Http\Controllers\Admin\TargetGroupTargetController;
use App\Http\Controllers\Admin\TargetGroupUserController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\Admin\UserTargetAccessController;
use App\Http\Middleware\EnsureLocalUserAccessEnabled;
use Illuminate\Support\Facades\Route;

Route::get('/admin/login', static fn () => view('admin.login'))
    ->middleware('guest')
    ->name('login');
Route::post('/admin/login', [AuthenticatedSessionController::class, 'store'])
    ->middleware(['guest', 'throttle:admin-login'])
    ->name('admin.login.store');

Route::middleware(['auth', EnsureLocalUserAccessEnabled::class])->prefix('admin')->name('admin.')->group(function (): void {
    Route::get('/', DashboardController::class)->name('dashboard');

    Route::get('/targets', [TargetController::class, 'index'])->name('targets.index');
    Route::get('/targets/create', [TargetController::class, 'create'])->name('targets.create');
    Route::post('/targets', [TargetController::class, 'store'])->name('targets.store');
    Route::get('/targets/{target:target_id}', [TargetController::class, 'show'])->name('targets.show');

    Route::get('/sites', [SiteController::class, 'index'])->name('sites.index');
    Route::get('/sites/create', [SiteController::class, 'create'])->name('sites.create');
    Route::post('/sites', [SiteController::class, 'store'])->name('sites.store');
    Route::get('/sites/{site:site_id}', [SiteController::class, 'show'])->name('sites.show');
    Route::put('/sites/{site:site_id}', [SiteController::class, 'update'])->name('sites.update');
    Route::delete('/sites/{site:site_id}', [SiteController::class, 'destroy'])->name('sites.destroy');

    Route::post('/sites/{site:site_id}/connect', [SiteConnectionController::class, 'connect'])->name('sites.connect');
    Route::post('/sites/{site:site_id}/reconnect', [SiteConnectionController::class, 'reconnect'])->name('sites.reconnect');
    Route::post('/sites/{site:site_id}/disconnect', [SiteConnectionController::class, 'disconnect'])->name('sites.disconnect');
    Route::post('/sites/{site:site_id}/test', [SiteConnectionController::class, 'test'])->name('sites.test');

    Route::post('/site-checks', [SiteCheckOperationController::class, 'store'])->name('site-checks.store');
    Route::get('/site-checks/{operation}', [SiteCheckOperationController::class, 'show'])->name('site-checks.show');
    Route::post('/site-checks/{operation}/advance', [SiteCheckOperationController::class, 'advance'])->name('site-checks.advance');
    Route::post('/site-checks/{operation}/targets/{target}/retry', [SiteCheckOperationController::class, 'retry'])->name('site-checks.retry');

    Route::get('/users', [UserController::class, 'index'])->name('users.index');
    Route::get('/users/create', [UserController::class, 'create'])->name('users.create');
    Route::post('/users', [UserController::class, 'store'])->name('users.store');
    Route::get('/users/{user}/edit', [UserController::class, 'edit'])->name('users.edit');
    Route::put('/users/{user}', [UserController::class, 'update'])->name('users.update');
    Route::get('/users/{user}/targets', [UserTargetAccessController::class, 'index'])->name('users.targets.index');
    Route::get('/users/{user}/targets/{target:target_id}/edit', [UserTargetAccessController::class, 'edit'])
        ->withoutScopedBindings()
        ->name('users.targets.edit');
    Route::put('/users/{user}/targets/{target:target_id}', [UserTargetAccessController::class, 'update'])
        ->withoutScopedBindings()
        ->name('users.targets.update');

    Route::get('/target-groups', [TargetGroupController::class, 'index'])->name('target-groups.index');
    Route::get('/target-groups/create', [TargetGroupController::class, 'create'])->name('target-groups.create');
    Route::post('/target-groups', [TargetGroupController::class, 'store'])->name('target-groups.store');
    Route::get('/target-groups/{targetGroup}/edit', [TargetGroupController::class, 'edit'])->name('target-groups.edit');
    Route::put('/target-groups/{targetGroup}', [TargetGroupController::class, 'update'])->name('target-groups.update');
    Route::delete('/target-groups/{targetGroup}', [TargetGroupController::class, 'destroy'])->name('target-groups.destroy');

    Route::get('/target-groups/{targetGroup}/targets', [TargetGroupTargetController::class, 'index'])->name('target-groups.targets.index');
    Route::get('/target-groups/{targetGroup}/targets/{target:target_id}/edit', [TargetGroupTargetController::class, 'edit'])
        ->withoutScopedBindings()
        ->name('target-groups.targets.edit');
    Route::put('/target-groups/{targetGroup}/targets/{target:target_id}', [TargetGroupTargetController::class, 'update'])
        ->withoutScopedBindings()
        ->name('target-groups.targets.update');

    Route::get('/target-groups/{targetGroup}/users', [TargetGroupUserController::class, 'index'])->name('target-groups.users.index');
    Route::get('/target-groups/{targetGroup}/users/{user}/edit', [TargetGroupUserController::class, 'edit'])->name('target-groups.users.edit');
    Route::put('/target-groups/{targetGroup}/users/{user}', [TargetGroupUserController::class, 'update'])->name('target-groups.users.update');

    Route::get('/oauth-clients', [OAuthClientAuthorizationsController::class, 'index'])
        ->name('oauth-clients.index');
    Route::delete('/oauth-clients/authorizations/{authorization}', [OAuthClientAuthorizationsController::class, 'revoke'])
        ->name('oauth-clients.revoke');

    Route::get('/activity', ActivityController::class)->name('activity');
    Route::view('/connection', 'admin.connection')
        ->middleware('can:gateway.connection.view')
        ->name('connection');
    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});
