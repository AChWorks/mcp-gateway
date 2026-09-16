<?php

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/health') {
    header('Content-Type: text/plain');
    echo 'ok';

    return;
}

if ($path === '/gzip-over') {
    $body = gzencode(str_repeat('g', 8192), 9);
    header('Content-Type: text/plain');
    header('Content-Encoding: gzip');
    header('Content-Length: '.strlen($body));
    echo $body;

    return;
}

if ($path === '/gzip-exact') {
    $body = gzencode(str_repeat('e', 1024), 9);
    header('Content-Type: text/plain');
    header('Content-Encoding: gzip');
    header('Content-Length: '.strlen($body));
    echo $body;

    return;
}

if ($path === '/unknown-over') {
    header('Content-Type: text/plain');
    echo str_repeat('u', 2048);

    return;
}

http_response_code(404);
echo 'not found';
