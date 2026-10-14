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

use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use McpGatewayUpdate\WebUpdater;

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
    require $basePath.'/vendor/autoload.php';
    $app = require $basePath.'/bootstrap/app.php';
    $app->make(ConsoleKernel::class)->bootstrap();
    require $basePath.'/update/WebUpdater.php';
    $updater = new WebUpdater($basePath, $basePath.'/update');

    $plan = $updater->preMigrationRecoveryStatus();
    printf("PRE_MIGRATION_PROOF=PASS phase=%s from=%s to=%s\n",
        $plan['phase'], $plan['from'], $plan['to']);

    if ($mode === '--check') {
        echo "CHECK_ONLY=PASS No updater stage, database migration, managed-code replacement, or maintenance transition requested; framework bootstrap may refresh package cache.\n";
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
    $origin = rtrim((string) config('app.url'), '/');
    $parts = parse_url($origin);
    if (! is_array($parts)
        || ! in_array(strtolower((string) ($parts['scheme'] ?? '')), ['https', 'http'], true)
        || ! is_string($parts['host'] ?? null)
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
        || (strtolower((string) $parts['scheme']) !== 'https'
            && ! (config('app.env') === 'testing' && in_array($parts['host'], ['127.0.0.1', 'localhost'], true)))) {
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
        if (config('app.env') !== 'testing' || ! is_array($fixture)
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
    } elseif (config('app.env') === 'testing' && $parts['scheme'] === 'http'
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
