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

$test = fixture();
try {
    $base = $test['base'];
    $private = $base.'/storage/app/private';
    $statePath = $private.'/update-state.json';

    // Run the actual temporary updater GET entrypoint using the matching
    // browser cookie, with a stub application bootstrap (GET exits before
    // invoking Laravel). No network, database or production setup is needed.
    foreach (['vendor', 'bootstrap'] as $dir) {
        verify(mkdir($base.'/'.$dir, 0700), 'entrypoint fixture '.$dir);
    }
    verify(copy(__DIR__.'/mcp-gateway-web-update-index.php', $base.'/public/update/index.php'),
        'real web updater entrypoint');
    verify(copy(__DIR__.'/mcp-gateway-web-updater.php', $base.'/update/WebUpdater.php'),
        'real updater implementation');
    file_put_contents($base.'/vendor/autoload.php', "<?php\n");
    file_put_contents($base.'/bootstrap/app.php', "<?php return new stdClass();\n");

    // Force BOTH completion-marker persistence and state unlink to fail after
    // successful simulated migrate/check/up. The old 'migrate' record remains
    // readable but can no longer prove whether postflight completed.
    verify(chmod($statePath, 0400), 'read-only migration state fixture');
    verify(chmod($private, 0500), 'non-writable private directory fixture');
    $warning = finalize($test['updater'], $test['state']);
    verify(is_string($warning)
        && str_contains($warning, 'completion state could not be persisted')
        && str_contains($warning, 'Private updater state could not be removed'),
        'combined completion-state write and state unlink failures produce warnings');
    $retained = json_decode((string) file_get_contents($statePath), true, 512, JSON_THROW_ON_ERROR);
    verify(($retained['phase'] ?? null) === 'migrate', 'the stale migration record really survived');
    $status = $test['updater']->browserUpdateStatus(str_repeat('a', 64));
    verify($status !== null && $status['phase'] === 'postflight-unverified' && ! $status['running'],
        'matching browser must receive an honest indeterminate postflight classification');
    verify($status['continuation'] === null && ! $status['expired']
        && $test['updater']->pendingContinuation(str_repeat('a', 64)) === null,
        'retained postflight state must never expose a resumable continuation or a false expired-session message');
    verify($test['updater']->browserUpdateStatus(str_repeat('c', 64)) === null,
        'indeterminate recovery status remains browser-bound');
    verify(is_dir($base.'/update') && is_dir($base.'/public/update'),
        'temporary updater stays available for authorized read-only recovery');

    $script = <<<'PHP_GET'
$_SERVER['HTTPS'] = 'on';
$_SERVER['SERVER_PORT'] = '443';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/update/';
$_COOKIE['mcp_gateway_update_session'] = $argv[2];
require $argv[1];
PHP_GET;
    $render = static function (string $browser) use ($base, $script): string {
        $command = [PHP_BINARY, '-r', $script, $base.'/public/update/index.php', $browser];
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        verify(is_resource($process), 'real GET recovery subprocess');
        fclose($pipes[0]);
        $html = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        verify(proc_close($process) === 0 && is_string($html), 'GET recovery response: '.$stderr);

        return $html;
    };
    $matchingGet = $render(str_repeat('a', 64));
    verify(str_contains($matchingGet, 'MCP Gateway Postflight Status Unverified')
        && str_contains($matchingGet, 'The updater recorded the start of database migration, but no final outcome.')
        && str_contains($matchingGet, 'Do not repeat migrations'),
        'authorized GET must explain uncertain postflight without asserting failure');
    verify(! str_contains($matchingGet, 'database may be partially migrated')
        && ! str_contains($matchingGet, 'name="continuation"'),
        'authorized GET must neither imply failed migration nor offer continuation');
    $otherGet = $render(str_repeat('c', 64));
    verify(str_contains($otherGet, 'Update Session Cannot Be Verified')
        && ! str_contains($otherGet, 'Postflight Status Unverified'),
        'cross-browser GET cannot inspect private recovery state');

    echo "Combined completion-write/unlink failure: stale migrate record maps to safe authorized GET.\n";
} finally {
    removeFixture($test['base']);
}
