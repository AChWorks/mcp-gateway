<?php

use App\Http\Controllers\OAuth\AuthorizationController;
use Illuminate\Support\Facades\Route;

Route::view('/', 'welcome');

Route::get('/oauth/authorize', [AuthorizationController::class, 'show'])
    ->middleware('throttle:oauth-browser');
Route::post('/oauth/authorize', [AuthorizationController::class, 'complete'])
    ->middleware('throttle:oauth-browser');
