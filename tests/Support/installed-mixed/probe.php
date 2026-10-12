<?php

declare(strict_types=1);

use App\Infrastructure\Http\SafeHttpClient;
use Illuminate\Contracts\Console\Kernel;

require dirname(__DIR__, 3).'/vendor/autoload.php';
$app = require dirname(__DIR__, 3).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$url = 'https://11.22.33.44/.well-known/oauth-protected-resource';
try {
    $out = app(SafeHttpClient::class)->get($url);
    echo 'PASS real outbound SafeHttpClient to installed WordPress: HTTP '.$out->status."\n";
    if ($out->status !== 200) {
        exit(1);
    }
} catch (Throwable $e) {
    $reason = property_exists($e, 'reason') ? $e->reason : $e::class;
    $previous = $e->getPrevious();
    fwrite(STDERR, 'Real Gateway outbound HTTPS probe: '.$reason.
        ', transport: '.($previous ? $previous::class.': '.$previous->getMessage() : $e->getMessage())."\n");
    exit(1);
}
