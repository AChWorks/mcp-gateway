<?php

use App\Http\Controllers\Admin\ActivityController;
use App\Http\Controllers\Admin\AuthenticatedSessionController;
use App\Http\Controllers\Admin\DashboardController;
use App\Http\Controllers\Admin\SiteCheckOperationController;
use App\Http\Controllers\Admin\SiteConnectionController;
use App\Http\Controllers\Admin\SiteController;
use App\Http\Controllers\Admin\SiteGroupController;
use App\Http\Controllers\Admin\SiteGroupSiteController;
use App\Http\Controllers\Admin\SiteGroupUserController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\Admin\UserSiteAccessController;
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
    Route::get('/users/{user}/sites', [UserSiteAccessController::class, 'index'])->name('users.sites.index');
    Route::get('/users/{user}/sites/{site:site_id}/edit', [UserSiteAccessController::class, 'edit'])
        ->withoutScopedBindings()
        ->name('users.sites.edit');
    Route::put('/users/{user}/sites/{site:site_id}', [UserSiteAccessController::class, 'update'])
        ->withoutScopedBindings()
        ->name('users.sites.update');

    Route::get('/site-groups', [SiteGroupController::class, 'index'])->name('site-groups.index');
    Route::get('/site-groups/create', [SiteGroupController::class, 'create'])->name('site-groups.create');
    Route::post('/site-groups', [SiteGroupController::class, 'store'])->name('site-groups.store');
    Route::get('/site-groups/{siteGroup}/edit', [SiteGroupController::class, 'edit'])->name('site-groups.edit');
    Route::put('/site-groups/{siteGroup}', [SiteGroupController::class, 'update'])->name('site-groups.update');
    Route::delete('/site-groups/{siteGroup}', [SiteGroupController::class, 'destroy'])->name('site-groups.destroy');

    Route::get('/site-groups/{siteGroup}/sites', [SiteGroupSiteController::class, 'index'])->name('site-groups.sites.index');
    Route::get('/site-groups/{siteGroup}/sites/{site:site_id}/edit', [SiteGroupSiteController::class, 'edit'])
        ->withoutScopedBindings()
        ->name('site-groups.sites.edit');
    Route::put('/site-groups/{siteGroup}/sites/{site:site_id}', [SiteGroupSiteController::class, 'update'])
        ->withoutScopedBindings()
        ->name('site-groups.sites.update');

    Route::get('/site-groups/{siteGroup}/users', [SiteGroupUserController::class, 'index'])->name('site-groups.users.index');
    Route::get('/site-groups/{siteGroup}/users/{user}/edit', [SiteGroupUserController::class, 'edit'])->name('site-groups.users.edit');
    Route::put('/site-groups/{siteGroup}/users/{user}', [SiteGroupUserController::class, 'update'])->name('site-groups.users.update');

    Route::get('/activity', ActivityController::class)->name('activity');
    Route::view('/connection', 'admin.connection')
        ->middleware('can:connection.view')
        ->name('connection');
    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});
