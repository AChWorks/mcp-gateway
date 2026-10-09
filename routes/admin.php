<?php

use App\Http\Controllers\Admin\ActivityController;
use App\Http\Controllers\Admin\AuthenticatedSessionController;
use App\Http\Controllers\Admin\DashboardController;
use App\Http\Controllers\Admin\OAuthClientAuthorizationsController;
use App\Http\Controllers\Admin\TargetConnectionController;
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
    Route::get('/targets/{target:target_id}/edit', [TargetController::class, 'edit'])->name('targets.edit');
    Route::put('/targets/{target:target_id}', [TargetController::class, 'update'])->name('targets.update');
    Route::delete('/targets/{target:target_id}', [TargetController::class, 'destroy'])->name('targets.destroy');
    Route::post('/targets/{target:target_id}/connect', [TargetConnectionController::class, 'connect'])->name('targets.connect');
    Route::post('/targets/{target:target_id}/reconnect', [TargetConnectionController::class, 'reconnect'])->name('targets.reconnect');
    Route::post('/targets/{target:target_id}/disconnect', [TargetConnectionController::class, 'disconnect'])->name('targets.disconnect');
    Route::post('/targets/{target:target_id}/test', [TargetConnectionController::class, 'test'])->name('targets.test');

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
