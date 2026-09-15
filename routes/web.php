<?php

use Illuminate\Support\Facades\Route;

Route::view('/', 'welcome');

require __DIR__.'/admin.php';
require __DIR__.'/oauth.php';
