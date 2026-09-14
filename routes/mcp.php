<?php

use App\Infrastructure\Mcp\BootstrapMcpEndpoint;
use Illuminate\Support\Facades\Route;

Route::match(
    ['POST', 'DELETE', 'OPTIONS'],
    '/_internal/mcp-bootstrap',
    [BootstrapMcpEndpoint::class, 'handle'],
);
