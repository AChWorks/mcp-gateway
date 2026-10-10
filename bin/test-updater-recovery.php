<?php

declare(strict_types=1);

require __DIR__.'/mcp-gateway-web-updater.php';

use McpGatewayUpdate\UpdateBusyException;
use McpGatewayUpdate\WebUpdater;

function check(bool $passed, string $description): void
{
    if (! $passed) {
        throw new RuntimeException('Updater recovery regression: '.$description);
    }
}

$base = sys_get_temp_dir().'/mcp-updater-state-'.bin2hex(random_bytes(8));
$private = $base.'/storage/app/private';
check(mkdir($private, 0700, true), 'temporary state directory');
$browser = str_repeat('a', 64);
$other = str_repeat('c', 64);
$token = str_repeat('b', 64);
$updater = new WebUpdater($base, $base.'/update');
$statePath = $private.'/update-state.json';
$lockPath = $private.'/update-execution.lock';

$write = static function (string $phase, int $expires) use ($statePath, $browser, $token): void {
    file_put_contents($statePath, json_encode([
        'phase' => $phase,
        'from' => '2.0.1',
        'to' => '2.0.2',
        'browser_token_hash' => hash('sha256', $browser),
        'continuation_token' => $token,
        'continuation_expires_at' => $expires,
    ], JSON_THROW_ON_ERROR));
};

try {
    check($updater->browserUpdateStatus($browser) === null, 'no state');
    $write('files-replaced', time() + 1800);
    check($updater->pendingContinuation($browser) === $token, 'resume in matching browser');
    check($updater->browserUpdateStatus($other) === null, 'no cross-browser status');
    $write('files-replaced', time() - 1);
    check($updater->pendingContinuation($browser) === null, 'expired continuation denied');
    try {
        $updater->finish($browser, $token);
        check(false, 'expired token accepted for finishing');
    } catch (RuntimeException $exception) {
        check(str_contains($exception->getMessage(), 'expired'), 'expired token rejected before mutation');
    }


    $write('files-replaced', time() + 1800);
    $lock = fopen($lockPath, 'c');
    check($lock !== false && flock($lock, LOCK_EX | LOCK_NB), 'exclusive operation lock');
    $status = $updater->browserUpdateStatus($browser);
    check($status !== null && $status['running'] && $status['continuation'] === null, 'no concurrent resume form');
    try {
        $updater->finish($browser, $token);
        check(false, 'duplicate finish was not rejected');
    } catch (UpdateBusyException) {
        // Rejected before migration or code mutation.
    }
    try {
        $updater->stage($browser);
        check(false, 'concurrent stage was not rejected');
    } catch (UpdateBusyException) {
    }
    flock($lock, LOCK_UN);
    fclose($lock);

    $write('migrate', time() + 1800);
    $status = $updater->browserUpdateStatus($browser);
    check($status !== null && ! $status['running'] && $status['continuation'] === null, 'interrupted migration not resumable');
    $write('failed-after-migration-start', time() + 1800);
    check($updater->failedState($browser) !== null, 'failed migration preserved');
    check($updater->pendingContinuation($browser) === null, 'failed migration not resumed');
    file_put_contents($statePath, '{invalid');
    check($updater->browserUpdateStatus($browser) === null, 'corrupt state cannot grant access');
    echo "Browser-bound recovery, expiry, serialization and interrupted-migration checks passed.\n";
} finally {
    foreach ([$statePath, $lockPath] as $path) {
        if (is_file($path)) {
            unlink($path);
        }
    }
    rmdir($private);
    rmdir($base.'/storage/app');
    rmdir($base.'/storage');
    rmdir($base);
}
