<?php

declare(strict_types=1);

/**
 * Dependency-free fail-closed regression for private browser continuation and
 * crash-durable journal. Never invokes the Laravel app or a live database.
 */

// The production updater calls PHP's unqualified fsync/rename inside its
// namespace. This isolated test process shadows those functions to simulate
// failures at precise journal-commit boundaries without any production hook.

namespace McpGatewayUpdate {
    function fsync($stream): bool
    {
        $uri = stream_get_meta_data($stream)['uri'] ?? '';
        $fault = $GLOBALS['mcp_gateway_journal_fault'] ?? null;
        if (($fault === 'file-fsync' && str_contains($uri, '.update-state-'))
            || ($fault === 'directory-fsync' && str_ends_with($uri, '/storage/app/private'))) {
            return false;
        }

        return \fsync($stream);
    }

    function rename(string $from, string $to): bool
    {
        if (($GLOBALS['mcp_gateway_journal_fault'] ?? null) === 'rename'
            && str_contains($from, '.update-state-')) {
            return false;
        }

        return \rename($from, $to);
    }
}

namespace {
    require __DIR__.'/mcp-gateway-web-updater.php';

    use McpGatewayUpdate\WebUpdater;

    $base = sys_get_temp_dir().'/mcp-gateway-journal-'.bin2hex(random_bytes(9));
    $private = $base.'/storage/app/private';
    if (! mkdir($private, 0700, true) && ! is_dir($private)) {
        throw new RuntimeException('Could not create disposable updater-state regression fixture.');
    }
    $now = 1700000000;
    $cookie = str_repeat('a', 64);
    $continuation = str_repeat('b', 64);
    $updater = new WebUpdater($base, $base.'/update', static fn (): int => $now);
    $write = new ReflectionMethod(WebUpdater::class, 'writeState');
    $assert = static function (bool $condition, string $reason): void {
        if (! $condition) {
            throw new RuntimeException($reason);
        }
    };
    $state = [
        'phase' => 'files-replaced',
        'migration_started' => false,
        'browser_token_hash' => hash('sha256', $cookie),
        'continuation_token' => $continuation,
        'continuation_expires_at' => $now + 240,
    ];
    $statePath = $private.'/update-state.json';
    $ledger = $private.'/independent-migration-ledger-proof.txt';
    file_put_contents($ledger, 'old ledger unchanged');
    $ledgerDigest = hash_file('sha256', $ledger);

    $removeFixture = static function (string $path) use (&$removeFixture): void {
        if (is_dir($path) && ! is_link($path)) {
            foreach (scandir($path) ?: [] as $entry) {
                if ($entry !== '.' && $entry !== '..') {
                    $removeFixture($path.'/'.$entry);
                }
            }
            rmdir($path);
        } elseif (file_exists($path) || is_link($path)) {
            unlink($path);
        }
    };

    try {
        $accounts = [
            'enabled Owner' => [['id' => 9, 'role' => 'owner', 'access_enabled' => true], '2.4.1', true],
            'PDO enabled Owner' => [['id' => '9', 'role' => 'owner', 'access_enabled' => '1'], '2.4.1', true],
            'Administrator' => [['id' => 9, 'role' => 'administrator', 'access_enabled' => 1], '2.4.1', false],
            'Operator' => [['id' => 9, 'role' => 'operator', 'access_enabled' => 1], '2.4.1', false],
            'Viewer' => [['id' => 9, 'role' => 'viewer', 'access_enabled' => 1], '2.4.1', false],
            'disabled Owner' => [['id' => 9, 'role' => 'owner', 'access_enabled' => 0], '2.4.1', false],
            'null role' => [['id' => 9, 'role' => null, 'access_enabled' => 1], '2.4.1', false],
            'unknown role' => [['id' => 9, 'role' => 'unknown', 'access_enabled' => 1], '2.4.1', false],
            'noncanonical Owner' => [['id' => 9, 'role' => 'Owner', 'access_enabled' => 1], '2.4.1', false],
            'malformed enabled flag' => [['id' => 9, 'role' => 'owner', 'access_enabled' => 'true'], '2.4.1', false],
            'missing enabled column' => [['id' => 9, 'role' => 'owner'], '1.1.10', false],
            'missing role column' => [['id' => 9, 'access_enabled' => 1], '1.1.10', false],
            'absent modern columns' => [['id' => 9], '2.4.1', false],
            'absent v1.2.1 columns' => [['id' => 9], '1.2.1', false],
            'absent identity' => [[], '1.1.2', false],
            'missing account' => [null, '1.1.2', false],
            'invalid identity' => [['id' => 'invalid'], '1.1.2', false],
            'supported v1.1.2 administrator' => [['id' => 9, 'email' => 'legacy@example.test'], '1.1.2', true],
            'supported v1.1.10 administrator' => [['id' => 9, 'email' => 'legacy@example.test'], '1.1.10', true],
            'unsupported earlier legacy version' => [['id' => 9], '1.0.0', false],
            'unknown later legacy version' => [['id' => 9], '1.1.11', false],
            'legacy prerelease' => [['id' => 9], '1.1.10-rc.1', false],
            'malformed legacy version' => [['id' => 9], 'unknown', false],
            'noncanonical legacy version' => [['id' => 9], '1.01.10', false],
            'legacy version with explicit Viewer role' => [['id' => 9, 'role' => 'viewer', 'access_enabled' => 1], '1.1.10', false],
        ];
        foreach ($accounts as $description => [$account, $version, $expected]) {
            $assert(WebUpdater::accountMayStart($account, $version) === $expected, 'Updater account boundary: '.$description);
        }

        $cases = [
            'removed' => null,
            'string' => (string) ($now + 240),
            'float' => (float) ($now + 240.5),
            'object' => (object) ['timestamp' => $now + 240],
            'array' => [$now + 240],
            'negative' => -1,
            'expired' => $now - 1,
            'equal now' => $now,
            'implausible future' => $now + WebUpdater::BROWSER_SESSION_TTL_SECONDS + 1,
        ];
        foreach ($cases as $label => $expiry) {
            $candidate = $state;
            if ($label === 'removed') {
                unset($candidate['continuation_expires_at']);
            } else {
                $candidate['continuation_expires_at'] = $expiry;
            }
            $write->invoke($updater, $candidate);
            $status = $updater->browserUpdateStatus($cookie);
            $assert(is_array($status) && $status['expired'] === true
                && $status['continuation'] === null,
                'GET exposed a continuation with invalid expiry: '.$label);

            $denied = false;
            try {
                $updater->finish($cookie, $continuation);
            } catch (RuntimeException) {
                $denied = true;
            }
            $assert($denied, 'Finish accepted invalid expiry: '.$label);
            $after = json_decode((string) file_get_contents($statePath), true, 512, JSON_THROW_ON_ERROR);
            $assert(($after['migration_started'] ?? null) === false
                && hash_file('sha256', $ledger) === $ledgerDigest,
                'Malformed continuation touched migration proof: '.$label);
        }

        $write->invoke($updater, $state);
        $status = $updater->browserUpdateStatus($cookie);
        $assert($status['continuation'] === $continuation && $status['expired'] === false,
            'Valid future continuation was rejected.');
        $assert((fileperms($statePath) & 0777) === 0600, 'Updater journal mode is not private.');

        // Simulate inability to flush the file, atomic rename failure and
        // inability to flush the renamed directory. None may return success.
        // The last case may show the new COMPLETE JSON in the page cache, but
        // still cannot authorize database mutation because writeState throws.
        foreach (['file-fsync', 'rename', 'directory-fsync'] as $fault) {
            $write->invoke($updater, $state);
            $next = $state;
            $next['phase'] = 'migrate';
            $next['migration_started'] = true;
            $GLOBALS['mcp_gateway_journal_fault'] = $fault;
            $blocked = false;
            try {
                $write->invoke($updater, $next);
            } catch (RuntimeException) {
                $blocked = true;
            } finally {
                unset($GLOBALS['mcp_gateway_journal_fault']);
            }
            $assert($blocked, 'Journal commit returned success after injected '.$fault);
            $readback = json_decode((string) file_get_contents($statePath), true, 512, JSON_THROW_ON_ERROR);
            $assert(is_array($readback), 'Journal was torn after '.$fault);
            if ($fault === 'directory-fsync') {
                $assert(($readback['migration_started'] ?? null) === true,
                    'Directory barrier failure lost an already renamed safe-denial marker.');
            } else {
                $assert(($readback['migration_started'] ?? null) === false,
                    'Incomplete journal commit prematurely changed the canonical state.');
            }
            $assert(hash_file('sha256', $ledger) === $ledgerDigest, 'Journal fault touched independent ledger');
        }

        foreach (['automatic', 'owner-local', null] as $origin) {
            $provenance = $state;
            $provenance['phase'] = 'recovery-files-restored';
            if ($origin !== null) {
                $provenance['recovery_origin'] = $origin;
            }
            $write->invoke($updater, $provenance);
            $status = $updater->browserUpdateStatus($cookie);
            $assert($status['recoveryOrigin'] === ($origin ?? 'unknown'),
                'Recovery provenance was invented or discarded.');
        }

        $migrating = $state;
        $migrating['phase'] = 'migrate';
        $migrating['migration_started'] = true;
        $write->invoke($updater, $migrating);
        $blocked = false;
        try {
            $updater->preMigrationRecoveryStatus();
        } catch (RuntimeException) {
            $blocked = true;
        }
        $assert($blocked, 'A committed migration-started journal permitted old-code recovery.');

        // An unsafe path must fail BEFORE replacing unrelated file contents.
        unlink($statePath);
        $unrelated = $base.'/unrelated-private-file';
        file_put_contents($unrelated, 'never overwrite');
        symlink($unrelated, $statePath);
        $blocked = false;
        try {
            $write->invoke($updater, $migrating);
        } catch (RuntimeException) {
            $blocked = true;
        }
        $assert($blocked && file_get_contents($unrelated) === 'never overwrite',
            'Symlink state path was followed during an atomic journal write.');
        unlink($statePath);

        // Render the actual temporary browser GET from this same disposable
        // state fixture; verify that no automatic or legacy record claims Owner
        // authorization just because recovery is in progress.
        $public = $base.'/public/update';
        mkdir($public, 0700, true);
        mkdir($base.'/update', 0700, true);
        mkdir($base.'/vendor', 0700, true);
        mkdir($base.'/bootstrap', 0700, true);
        file_put_contents($base.'/bootstrap/app.php', "<?php return new stdClass();\n");
        file_put_contents($base.'/vendor/autoload.php', "<?php\n");
        copy(__DIR__.'/mcp-gateway-web-update-index.php', $public.'/index.php');
        copy(__DIR__.'/mcp-gateway-web-updater.php', $base.'/update/WebUpdater.php');
        $render = static function () use ($public, $cookie): string {
            $script = <<<'PHP_GET'
$_SERVER['HTTPS'] = 'on';
$_SERVER['SERVER_PORT'] = '443';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/update/';
$_COOKIE['mcp_gateway_update_session'] = $argv[2];
require $argv[1];
PHP_GET;
            $p = proc_open([PHP_BINARY, '-r', $script, $public.'/index.php', $cookie],
                [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (! is_resource($p)) {
                throw new RuntimeException('Browser recovery GET could not be invoked.');
            }
            $html = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            if (proc_close($p) !== 0 || ! is_string($html)) {
                throw new RuntimeException('Browser recovery GET failed: '.$stderr);
            }

            return $html;
        };
        foreach ([
            'automatic' => 'The updater automatically attempted a code-only restore',
            'owner-local' => 'An Owner with local shell access initiated guarded code-only recovery',
            'legacy-unknown' => 'does not establish whether the restore was automatic or Owner-initiated',
        ] as $kind => $expected) {
            $stateGet = $state;
            $stateGet['phase'] = 'recovery-files-restored';
            if ($kind !== 'legacy-unknown') {
                $stateGet['recovery_origin'] = $kind;
            }
            $write->invoke($updater, $stateGet);
            $html = $render();
            $assert(str_contains($html, $expected), 'Browser misreported recovery origin: '.$kind);
            if ($kind !== 'owner-local') {
                $assert(! str_contains($html, 'An Owner with local shell access initiated guarded code-only recovery'),
                    'Browser falsely claimed explicit Owner recovery.');
            }
        }

        echo "Updater state, durable-commit faults, browser provenance and continuation guards: PASS\n";
    } finally {
        $removeFixture($base);
    }
}
