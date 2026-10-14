<?php

declare(strict_types=1);

/**
 * Temporary, private CLI recovery entry bundled in update/Recover.php.
 *
 * Operator shell access is the authority boundary. Never expose this file
 * through public/ or a web route. No database write, DB restore, key rotation,
 * Target disconnect, OAuth replay or unauthenticated recovery URL is offered.
 *
 * Run as the actual, unprivileged LSAPI vhost PHP UID (NOT root).
 */

use Dotenv\Dotenv;
use McpGatewayUpdate\WebUpdater;
use Pdo\Mysql;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

$arguments = $argv ?? [];
$mode = $arguments[1] ?? '';
if (count($arguments) !== 2 || ! in_array($mode, ['--check', '--recover'], true)) {
    fwrite(STDERR, "Usage: php update/Recover.php --check|--recover\nRun as the site's unprivileged LSAPI PHP worker, never root.\n");
    exit(2);
}

$basePath = dirname(__DIR__);
$statePath = $basePath.'/storage/app/private/update-state.json';
$maintenancePath = $basePath.'/storage/framework/down';

try {
    if (! function_exists('posix_geteuid') || posix_geteuid() === 0) {
        throw new RuntimeException('Run recovery as the real unprivileged LSAPI PHP worker; root is forbidden.');
    }
    $workerUid = posix_geteuid();
    if (is_link($statePath) || ! is_file($statePath) || fileowner($statePath) !== $workerUid) {
        throw new RuntimeException('The update state is missing or belongs to another PHP worker. Stop and reconcile ownership.');
    }
    if (is_link($maintenancePath)
        || (is_file($maintenancePath) && fileowner($maintenancePath) !== $workerUid)) {
        throw new RuntimeException('The maintenance marker does not belong to this PHP worker.');
    }
    if (! is_file($basePath.'/update/WebUpdater.php') || is_link($basePath.'/update/WebUpdater.php')) {
        throw new RuntimeException('The private updater implementation is missing or invalid.');
    }

    if ($mode === '--recover') {
        // All child Artisan commands inherit this. Never run root Artisan
        // housekeeping with umask 077: packages/services.php must remain
        // accessible to the actual LSAPI worker; config.php stays private.
        umask(0022);
    }

    chdir($basePath);
    require $basePath.'/update/WebUpdater.php';

    // The newly staged managed vendor/bootstrap files might be unusable on
    // this host. Do NOT load them even for --check: that is precisely the
    // stranded pre-migration condition this private Owner path must handle.
    //
    // WebUpdater validates the full old snapshot, manifest, expected package,
    // state, maintenance marker and lock BEFORE calling this closure. Only
    // then may it use the authenticated old vendor's dotenv parser (without
    // starting either application's Laravel kernel).
    $recoveryEnvironment = null;
    $readEnvironment = static function (string $backup) use ($basePath, &$recoveryEnvironment): array {
        if (is_array($recoveryEnvironment)) {
            return $recoveryEnvironment;
        }
        $autoload = $backup.'/files/vendor/autoload.php';
        if (! is_file($autoload) || is_link($autoload)) {
            throw new RuntimeException('Authenticated previous runtime has no safe Composer autoloader.');
        }
        require_once $autoload;
        $envPath = $basePath.'/.env';
        if (is_link($envPath) || ! is_file($envPath) || ! is_readable($envPath)) {
            throw new RuntimeException('Original private .env is missing or unreadable.');
        }
        $raw = file_get_contents($envPath);
        if (! is_string($raw) || ! class_exists(Dotenv::class)) {
            throw new RuntimeException('Previous-runtime environment parser is unavailable.');
        }
        $values = Dotenv::parse($raw);
        if (! is_array($values)) {
            throw new RuntimeException('Previous-runtime environment is invalid.');
        }

        // Refuse an ambiguous database identity when process-level overrides
        // could have made the running app use a different DB than private .env.
        foreach (['DB_URL', 'DB_CONNECTION', 'DB_HOST', 'DB_PORT', 'DB_SOCKET',
            'DB_DATABASE', 'DB_USERNAME', 'DB_PASSWORD', 'MYSQL_ATTR_SSL_CA',
            'APP_URL', 'APP_ENV'] as $name) {
            $configured = $values[$name] ?? null;
            if ($configured !== null && ! is_string($configured)) {
                throw new RuntimeException('Recovery configuration contains a non-string critical value.');
            }
            foreach ([getenv($name), $_ENV[$name] ?? false, $_SERVER[$name] ?? false] as $override) {
                if ($override !== false && (string) $override !== (string) $configured) {
                    throw new RuntimeException('Environment overrides the private recovery identity; reconcile without code rollback.');
                }
            }
        }

        // If the PREVIOUS installed runtime had a Laravel config cache,
        // it (not a possibly later .env edit) determined the original DB.
        // Require that authenticated old-cache identity matches preserved
        // private .env before any recovery ledger query. Never execute the
        // currently staged candidate's generated configuration.
        $oldCache = $backup.'/files/bootstrap/cache/config.php';
        if (file_exists($oldCache)) {
            if (is_link($oldCache) || ! is_file($oldCache)) {
                throw new RuntimeException('Original configuration cache has an unsafe filesystem type.');
            }
            $cached = require $oldCache;
            if (! is_array($cached) || ! is_array($cached['database'] ?? null)
                || ! is_array($cached['app'] ?? null)) {
                throw new RuntimeException('Original runtime configuration cache is invalid.');
            }
            $driver = (string) ($values['DB_CONNECTION'] ?? 'mariadb');
            $originalDriver = $cached['database']['default'] ?? null;
            $connection = $cached['database']['connections'][$driver] ?? null;
            if (! is_string($originalDriver) || $originalDriver !== $driver
                || ! is_array($connection)
                || isset($connection['read']) || isset($connection['write'])) {
                throw new RuntimeException('Original runtime database identity cannot be reconciled.');
            }
            foreach ([
                'DB_HOST' => ['host', '127.0.0.1'],
                'DB_PORT' => ['port', '3306'],
                'DB_DATABASE' => ['database', ''],
                'DB_USERNAME' => ['username', ''],
                'DB_PASSWORD' => ['password', ''],
                'DB_SOCKET' => ['unix_socket', ''],
                'DB_URL' => ['url', ''],
            ] as $name => [$field, $fallback]) {
                $actual = $connection[$field] ?? '';
                $expected = $values[$name] ?? $fallback;
                if (! is_scalar($actual) || (string) $actual !== (string) $expected) {
                    throw new RuntimeException('Original runtime database identity differs from preserved configuration.');
                }
            }
            if (($cached['app']['url'] ?? null) !== ($values['APP_URL'] ?? null)
                || ($cached['app']['env'] ?? null) !== ($values['APP_ENV'] ?? 'production')) {
                throw new RuntimeException('Original runtime HTTP identity differs from preserved configuration.');
            }
        }

        // The staged candidate may have a malformed bootstrap/cache/config.php.
        // It MUST NOT block proof against the verified previous snapshot;
        // no part of that candidate cache is executed or trusted.
        $recoveryEnvironment = $values;

        return $values;
    };

    $readOldMigrationLedger = static function (string $backup) use ($readEnvironment): array {
        $env = $readEnvironment($backup);
        $get = static fn (string $name, string $fallback = ''): string => (string) ($env[$name] ?? $fallback);
        $driver = $get('DB_CONNECTION', 'mariadb');
        if (! in_array($driver, ['mysql', 'mariadb'], true) || $get('DB_URL') !== '') {
            throw new RuntimeException('Standalone Owner recovery only accepts a verified direct MariaDB/MySQL configuration.');
        }
        $host = $get('DB_HOST', '127.0.0.1');
        $port = $get('DB_PORT', '3306');
        $database = $get('DB_DATABASE');
        $username = $get('DB_USERNAME');
        $password = $get('DB_PASSWORD');
        $socket = $get('DB_SOCKET');
        $sslCa = $get('MYSQL_ATTR_SSL_CA');
        if ($database === '' || $username === '' || $host === ''
            || preg_match('/^[0-9]{1,5}$/D', $port) !== 1 || (int) $port < 1 || (int) $port > 65535
            || strpbrk($database, ";\r\n\0") !== false
            || strpbrk($host, ";\r\n\0") !== false
            || ($socket !== '' && ($socket[0] !== '/' || strpbrk($socket, ";\r\n\0") !== false))) {
            throw new RuntimeException('Recovery database connection identity is incomplete or unsupported.');
        }

        $dsn = $socket !== ''
            ? 'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4'
            : 'mysql:host='.$host.';port='.$port.';dbname='.$database.';charset=utf8mb4';
        $options = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 5, PDO::ATTR_EMULATE_PREPARES => false];
        if ($sslCa !== '') {
            if (! is_file($sslCa) || is_link($sslCa)) {
                throw new RuntimeException('The configured database TLS CA cannot be verified.');
            }
            $options[Mysql::ATTR_SSL_CA] = $sslCa;
        }

        try {
            $pdo = new PDO($dsn, $username, $password, $options);
            if ($pdo->query('SELECT DATABASE()')->fetchColumn() !== $database) {
                throw new RuntimeException('Recovery database identity does not match private configuration.');
            }
            $rows = $pdo->query('SELECT migration FROM migrations')->fetchAll(PDO::FETCH_COLUMN);
            if (! is_array($rows) || ! array_is_list($rows)
                || count(array_filter($rows, 'is_string')) !== count($rows)) {
                throw new RuntimeException('Recovery migration ledger returned an invalid result.');
            }

            return $rows;
        } catch (PDOException $exception) {
            // Never put DSNs, query details or credentials into output/logs.
            throw new RuntimeException('Could not independently verify the previous database migration ledger.', 0, $exception);
        }
    };

    $updater = new WebUpdater($basePath, $basePath.'/update', null, $readOldMigrationLedger);

    $plan = $updater->preMigrationRecoveryStatus();
    printf("PRE_MIGRATION_PROOF=PASS phase=%s from=%s to=%s\n",
        $plan['phase'], $plan['from'], $plan['to']);

    if ($mode === '--check') {
        echo "CHECK_ONLY=PASS No candidate Laravel bootstrap, updater stage, database migration, managed-code replacement, or maintenance transition requested.\n";
        exit(0);
    }

    $plan = $updater->recoverPreMigrationFiles();
    printf("RECOVERY_FILES=%s Code-only snapshot retained; database untouched.\n", $plan['phase']);

    // A new process MUST bootstrap the restored runtime. The currently
    // executing PHP process still contains classes from the newer candidate.
    // Suppress child stdout/stderr: Artisan errors can contain environment
    // details. A safe reference and command name suffice for diagnostics.
    $runArtisan = static function (string $command) use ($basePath): void {
        $process = proc_open(
            [PHP_BINARY, $basePath.'/artisan', $command, '--no-interaction', '--no-ansi'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            $basePath,
        );
        if (! is_resource($process)) {
            throw new RuntimeException('Could not launch restored-runtime check '.$command.'.');
        }
        $status = proc_close($process);
        if ($status !== 0) {
            throw new RuntimeException('Restored-runtime '.$command.' failed; maintenance/state retained where possible.');
        }
        echo 'RESTORED_ARTISAN_'.strtoupper(str_replace(':', '_', $command))."=PASS\n";
    };

    $runArtisan('optimize:clear');
    $runArtisan('gateway:check');

    $cacheDir = $basePath.'/bootstrap/cache';
    if (is_link($cacheDir) || ! is_dir($cacheDir) || ! is_readable($cacheDir) || ! is_writable($cacheDir)) {
        throw new RuntimeException('bootstrap/cache is not accessible to the actual PHP worker.');
    }
    // PHP's generated package/service manifests are not secret; fix ONLY
    // these two paths if required, never recursive chmod/chown or config.php.
    foreach (['packages.php', 'services.php'] as $filename) {
        $path = $cacheDir.'/'.$filename;
        if (! file_exists($path)) {
            continue;
        }
        if (is_link($path) || ! is_file($path)) {
            throw new RuntimeException('Generated Laravel cache manifest has an unsafe filesystem type.');
        }
        if (! is_readable($path) || ! chmod($path, 0644)) {
            throw new RuntimeException('Generated Laravel cache manifest is not safely readable by the PHP worker.');
        }
    }
    $configCache = $cacheDir.'/config.php';
    if (is_file($configCache) && (is_link($configCache) || ! chmod($configCache, 0600))) {
        throw new RuntimeException('Private Laravel configuration-cache permissions could not be secured.');
    }

    $runArtisan('up');
    $updater->markPreMigrationRecoveryStatus('recovery-http-unverified');
    echo "MAINTENANCE_EXITED=PASS HTTP verification is required before recovery completion.\n";

    // Read only public, non-destructive endpoints at the configured origin.
    // Loopback plaintext is allowed solely in explicitly disposable test env.
    // This was loaded from the authenticated old snapshot + unchanged .env,
    // not from the broken staged candidate or its generated config cache.
    $env = $readEnvironment($plan['backup']);
    $appEnvironment = (string) ($env['APP_ENV'] ?? 'production');
    $origin = rtrim((string) ($env['APP_URL'] ?? ''), '/');
    $parts = parse_url($origin);
    if (! is_array($parts)
        || ! in_array(strtolower((string) ($parts['scheme'] ?? '')), ['https', 'http'], true)
        || ! is_string($parts['host'] ?? null)
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
        || (strtolower((string) $parts['scheme']) !== 'https'
            && ! ($appEnvironment === 'testing' && in_array($parts['host'], ['127.0.0.1', 'localhost'], true)))) {
        throw new RuntimeException('Configured APP_URL is not an approved HTTP readiness origin.');
    }
    if (! function_exists('curl_init')) {
        throw new RuntimeException('PHP cURL is unavailable for required web-worker readiness checks.');
    }
    $readinessHeaders = ['Cache-Control: no-cache', 'Pragma: no-cache'];
    $requestOrigin = $origin;
    $fixtureOrigin = getenv('MCP_GATEWAY_RECOVERY_TEST_LOOPBACK');
    if ($fixtureOrigin !== false) {
        // Strictly scoped to disposable testing; production HTTP readiness
        // always uses the installation's configured HTTPS APP_URL.
        $fixture = parse_url($fixtureOrigin);
        if ($appEnvironment !== 'testing' || ! is_array($fixture)
            || ($fixture['scheme'] ?? null) !== 'http'
            || ($fixture['host'] ?? null) !== '127.0.0.1'
            || ! is_int($fixture['port'] ?? null) || $fixture['port'] < 1024
            || isset($fixture['path']) || isset($fixture['query']) || isset($fixture['fragment'])
            || isset($fixture['user']) || isset($fixture['pass'])) {
            throw new RuntimeException('Disposable HTTP recovery test override is invalid.');
        }
        $requestOrigin = $fixtureOrigin;
        $readinessHeaders[] = 'Host: '.$parts['host'];
        $readinessHeaders[] = 'X-Forwarded-Proto: https';
    } elseif ($appEnvironment === 'testing' && $parts['scheme'] === 'http'
        && in_array($parts['host'], ['127.0.0.1', 'localhost'], true)) {
        $readinessHeaders[] = 'X-Forwarded-Proto: https';
    }
    foreach (['/up', '/admin/login', '/oauth/client.json', '/oauth/jwks.json', '/.well-known/oauth-authorization-server'] as $route) {
        $curl = curl_init($requestOrigin.$route);
        if ($curl === false) {
            throw new RuntimeException('Could not initialize origin HTTP readiness check.');
        }
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => $readinessHeaders,
            CURLOPT_USERAGENT => 'MCP-Gateway-PreMigration-Recovery-Readiness/1',
            CURLOPT_WRITEFUNCTION => static fn ($handle, string $body): int => strlen($body),
        ]);
        $ok = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        if ($ok !== true || $httpCode !== 200) {
            throw new RuntimeException('HTTP readiness failed for '.$route.' (HTTP '.$httpCode.', expected 200). Retained recovery state; inspect the first web-PHP bootstrap error.');
        }
        echo 'HTTP_READINESS_'.strtoupper(str_replace(['/', '.', '-'], ['_', '_', '_'], $route))."=200\n";
    }

    $updater->markPreMigrationRecoveryStatus('recovery-completed');
    echo "RECOVERY_COMPLETE=PASS Previous managed code restored; public HTTP bootstrap verified.\n";
    echo "Operator must still verify authenticated Admin and read-only WordPress Target/OAuth behavior. Original backup, archive and updater state are deliberately retained.\n";
    exit(0);
} catch (Throwable $exception) {
    $reference = bin2hex(random_bytes(8));
    error_log('MCP Gateway operator-local recovery blocked reference='.$reference.' class='.get_class($exception));
    $message = preg_replace('/[\r\n\t]+/', ' ', $exception->getMessage());
    $message = is_string($message) ? substr($message, 0, 250) : 'Unknown recovery precondition';
    fwrite(STDERR, "RECOVERY_NOT_VERIFIED reference=$reference: ".$message."\n");
    fwrite(STDERR, "Do not repeat migrations, delete state/backup, change OAuth/Target, or assume HTTP readiness.\n");
    exit(1);
}
