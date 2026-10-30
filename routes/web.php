<?php

use App\Application\Admin\AdminNavigation;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/', static fn (Request $request, AdminNavigation $navigation) => $request->user() instanceof User
    ? redirect()->to($navigation->landingUrl($request->user()))
    : view('welcome'));

require __DIR__.'/admin.php';
require __DIR__.'/oauth.php';
