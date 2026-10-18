<?php

declare(strict_types=1);

use App\Application\Files\ChatGptFileCapacity;
use App\Infrastructure\Http\OutboundRequestException;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 6 || ! in_array($argv[2], ['a', 'b'], true)
    || ! in_array($argv[3], ['wordpress', 'ssh'], true)
    || ! ctype_digit($argv[4]) || ! ctype_digit($argv[5])) {
    fwrite(STDERR, "usage: chatgpt_file_capacity_race.php <private-test-barrier> <a|b> <mode> <bytes> <max_active>\n");
    exit(2);
}

[, $directory, $workerId, $mode, $bytesArg, $activeArg] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$database = (string) DB::connection()->getDatabaseName();
if (! app()->environment('testing')
    || ! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)
    || preg_match('/(?:^|[_-])(?:test|testing|ci)(?:[_-]|$)/i', $database) !== 1) {
    fwrite(STDERR, "Independent DB concurrency workers require an isolated test MariaDB.\n");
    exit(2);
}

config()->set('bridge.file_input.capacity.max_active', (int) $activeArg);
config()->set('bridge.file_input.capacity.wordpress_max_active', 2);
config()->set('bridge.file_input.capacity.ssh_max_active', 2);
config()->set('bridge.file_input.capacity.max_reserved_bytes', 1048576);

$until = microtime(true) + 15;
$wait = static function (string $path) use ($until): void {
    while (! is_file($path)) {
        if (microtime(true) >= $until) {
            throw new RuntimeException('The private test barrier timed out.');
        }
        usleep(10000);
    }
};

try {
    file_put_contents($directory.'/ready-'.$workerId, 'ready');
    $wait($directory.'/go');

    try {
        $lease = $app->make(ChatGptFileCapacity::class)->reserve($mode, (int) $bytesArg, 20);
    } catch (OutboundRequestException $error) {
        file_put_contents($directory.'/result-'.$workerId, json_encode([
            'status' => 'denied', 'reason' => $error->reason,
        ], JSON_THROW_ON_ERROR));
        exit(0);
    }

    file_put_contents($directory.'/admitted-'.$workerId, 'admitted');
    try {
        $wait($directory.'/release');
    } finally {
        $lease->release();
    }
    file_put_contents($directory.'/result-'.$workerId,
        json_encode(['status' => 'admitted'], JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}
