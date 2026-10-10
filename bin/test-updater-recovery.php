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
$now = 2000000000;
$clock = static function () use (&$now): int {
    return $now;
};
$updater = new WebUpdater($base, $base.'/update', $clock);
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
    // The clock advances deterministically: late preflight does not consume a
    // continuation token, and the full TTL begins after staging completes.
    $now += 3600; // Simulated prolonged backup/staging after preflight.
    $write('files-replaced', $now + WebUpdater::BROWSER_SESSION_TTL_SECONDS);
    check($updater->pendingContinuation($browser) === $token, 'long stage retains full continuation lifetime');
    check($updater->browserUpdateStatus($other) === null, 'no cross-browser status');
    $now += WebUpdater::BROWSER_SESSION_TTL_SECONDS - 1;
    check($updater->pendingContinuation($browser) === $token, 'session valid immediately before expiry');
    $now += 2;
    check($updater->pendingContinuation($browser) === null, 'expired continuation denied');
    try {
        $updater->finish($browser, $token);
        check(false, 'expired token accepted for finishing');
    } catch (RuntimeException $exception) {
        check(str_contains($exception->getMessage(), 'expired'), 'expired token rejected before mutation');
    }

    $write('files-replaced', $now + WebUpdater::BROWSER_SESSION_TTL_SECONDS);
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

    $write('migrate', $now + WebUpdater::BROWSER_SESSION_TTL_SECONDS);
    $status = $updater->browserUpdateStatus($browser);
    check($status !== null && $status['phase'] === 'postflight-unverified'
        && ! $status['running'] && $status['continuation'] === null,
        'idle migration record is indeterminate and not resumable');
    $write('migrate', $now - 1);
    $status = $updater->browserUpdateStatus($browser);
    check($status !== null && $status['phase'] === 'postflight-unverified'
        && ! $status['expired'] && $status['continuation'] === null,
        'expired stale migrate record must not imply the final step never finished');
    $write('failed-after-migration-start', $now + WebUpdater::BROWSER_SESSION_TTL_SECONDS);
    check($updater->failedState($browser) !== null, 'failed migration preserved');
    check($updater->pendingContinuation($browser) === null, 'failed migration not resumed');
    $write('completed', $now - 1);
    $completed = $updater->browserUpdateStatus($browser);
    check($completed !== null && $completed['phase'] === 'completed'
        && $completed['continuation'] === null, 'completed state never appears as a migration failure or restart');
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
