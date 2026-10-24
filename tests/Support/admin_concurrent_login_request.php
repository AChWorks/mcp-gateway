<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Request;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 5 && $argc !== 6) {
    fwrite(STDERR, "Expected barrier, ready, email, test IP and optional repetition count.\n");
    exit(2);
}
[, $barrier, $ready, $email, $ip] = $argv;
$repetitions = isset($argv[5]) ? (int) $argv[5] : 1;
if ($repetitions < 1 || $repetitions > 8) {
    fwrite(STDERR, "Invalid bounded fixture repetition count.\n");
    exit(2);
}

// Before bootstrap: Laravel's RateLimiter singleton is created during
// AppServiceProvider boot, so switching cache config afterwards cannot
// replace its already resolved array-backed repository in testing.
putenv('CACHE_STORE=file');
$_ENV['CACHE_STORE'] = 'file';
$_SERVER['CACHE_STORE'] = 'file';
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(ConsoleKernel::class)->bootstrap();
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

$kernel = $app->make(HttpKernel::class);
$codes = [];
for ($i = 0; $i < $repetitions; $i++) {
    // Each warm-up request has a different IP, so the only shared admission
    // boundary under test is the canonical database account identity.
    $address = $repetitions === 1 ? $ip : long2ip((int) ip2long($ip) + $i);
    $request = Request::create('/admin/login', 'POST', [
        'email' => $email,
        'password' => 'deliberately-wrong-fixture-password',
    ], [], [], ['REMOTE_ADDR' => $address, 'HTTP_ACCEPT' => 'text/html']);
    $codes[] = $kernel->handle($request)->getStatusCode();
}
echo json_encode(['status' => end($codes), 'statuses' => $codes], JSON_THROW_ON_ERROR);
