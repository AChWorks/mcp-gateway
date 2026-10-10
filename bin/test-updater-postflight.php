<?php

declare(strict_types=1);

require __DIR__.'/mcp-gateway-web-updater.php';

use McpGatewayUpdate\WebUpdater;

function verify(bool $ok, string $description): void
{
    if (! $ok) {
        throw new RuntimeException('Postflight regression: '.$description);
    }
}

/** @return array{base:string,updater:WebUpdater,state:array<string,mixed>} */
function fixture(): array
{
    $base = sys_get_temp_dir().'/gateway-postflight-'.bin2hex(random_bytes(8));
    foreach (['storage/app/private/update-backups', 'public/update', 'update'] as $dir) {
        verify(mkdir($base.'/'.$dir, 0700, true), 'fixture directory '.$dir);
    }

    $state = [
        'phase' => 'migrate',
        'migration_started' => true,
        'from' => '2.0.1',
        'to' => '2.0.2',
        'browser_token_hash' => hash('sha256', str_repeat('a', 64)),
        'continuation_token' => str_repeat('b', 64),
    ];
    verify(file_put_contents($base.'/storage/app/private/update-state.json', json_encode($state, JSON_THROW_ON_ERROR)) !== false, 'initial state');
    file_put_contents($base.'/public/update/index.php', 'temporary public updater');
    file_put_contents($base.'/update/WebUpdater.php', 'temporary private updater');

    return [
        'base' => $base,
        'updater' => new WebUpdater($base, $base.'/update'),
        'state' => $state,
    ];
}

function finalize(WebUpdater $updater, array $state): ?string
{
    return (new ReflectionMethod(WebUpdater::class, 'finishSuccessfulUpdate'))
        ->invoke($updater, $state, '2.0.2');
}

function removeFixture(string $base): void
{
    $walk = static function (string $path) use (&$walk): void {
        if (! is_dir($path) || is_link($path)) {
            if (file_exists($path) || is_link($path)) {
                unlink($path);
            }

            return;
        }

        chmod($path, 0700);
        foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) {
            $walk($entry->getPathname());
        }
        rmdir($path);
    };
    $walk($base);
}

if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
    echo "Filesystem permission regressions require an unprivileged user; skipped under root.\n";
    exit(0);
}

$test = fixture();
try {
    $base = $test['base'];
    $backups = $base.'/storage/app/private/update-backups';
    foreach (['0000-old', '2099-a', '2099-b', '2099-c'] as $name) {
        verify(mkdir($backups.'/'.$name, 0700, true), 'fixture backup '.$name);
    }
    verify(mkdir($backups.'/0000-old/blocked', 0700), 'blocked backup');
    file_put_contents($backups.'/0000-old/blocked/sentinel', 'retained recovery evidence');
    chmod($backups.'/0000-old/blocked', 0500);

    $warning = finalize($test['updater'], $test['state']);
    verify(is_string($warning) && str_contains($warning, 'code backups could not be pruned'), 'prune failure must become success warning');
    verify(! is_file($base.'/storage/app/private/update-state.json'), 'cleanup should still remove obsolete state');
    verify(! is_dir($base.'/update') && ! is_dir($base.'/public/update'), 'temporary updater cleanup continues after prune failure');
    verify(is_file($backups.'/0000-old/blocked/sentinel'), 'failed backup prune does not discard backup');
    echo "Successful postflight with failed backup pruning: success-with-warning, not migration failure.\n";
} finally {
    removeFixture($test['base']);
}

$test = fixture();
try {
    $base = $test['base'];
    $private = $base.'/storage/app/private';
    chmod($private, 0500);
    $warning = finalize($test['updater'], $test['state']);
    verify(is_string($warning) && str_contains($warning, 'Private updater state could not be removed'), 'state unlink failure warning');
    verify(is_file($private.'/update-state.json'), 'unremovable state retained for review');
    $status = $test['updater']->browserUpdateStatus(str_repeat('a', 64));
    verify($status !== null && $status['phase'] === 'completed' && $status['continuation'] === null,
        'completed state must not show interrupted-migration or resumption');
    verify(is_dir($base.'/update') && is_dir($base.'/public/update'), 'temporary updater retained if state cannot be removed');
    echo "Successful postflight with stale state: completed marker and actionable cleanup warning.\n";
} finally {
    removeFixture($test['base']);
}
