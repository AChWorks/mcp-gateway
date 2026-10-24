<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Request;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 5) {
    fwrite(STDERR, "Expected barrier, ready, submitted email and distinct test IP.\n");
    exit(2);
}
[, $barrier, $ready, $email, $ip] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(ConsoleKernel::class)->bootstrap();
// Reuse one isolated file-backed limiter across separate PHP processes.
config()->set('cache.default', 'file');
config()->set('cache.limiter', 'file');

if (! touch($ready)) {
    fwrite(STDERR, "Worker readiness failure.\n");
    exit(2);
}
$deadline = microtime(true) + 15;
while (! is_file($barrier)) {
    if (microtime(true) >= $deadline) {
        fwrite(STDERR, "Worker start barrier timed out.\n");
        exit(2);
    }
    usleep(1000);
}

$request = Request::create('/admin/login', 'POST', [
    'email' => $email,
    'password' => 'deliberately-wrong-fixture-password',
], [], [], ['REMOTE_ADDR' => $ip, 'HTTP_ACCEPT' => 'text/html']);
$response = $app->make(HttpKernel::class)->handle($request);
echo json_encode(['status' => $response->getStatusCode()], JSON_THROW_ON_ERROR);
