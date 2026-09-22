<?php

namespace App\Support;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PDO;
use RuntimeException;
use Throwable;

final class SimpleWebInstaller
{
    public const MINIMUM_PHP_VERSION = '8.4.1';

    /** @var list<string> */
    private const REQUIRED_EXTENSIONS = [
        'curl',
        'mbstring',
        'openssl',
        'pdo_mysql',
        'sodium',
    ];

    /** @var list<string> */
    private const SUPPORTED_DATABASE_DRIVERS = ['mariadb', 'mysql'];

    /** @return array<string, bool> */
    public static function preflight(string $basePath, bool $https): array
    {
        $checks = [
            'PHP >= '.self::MINIMUM_PHP_VERSION => version_compare(PHP_VERSION, self::MINIMUM_PHP_VERSION, '>='),
            'HTTPS is enabled for the installer' => $https,
            'Production dependencies are bundled' => is_file($basePath.'/vendor/autoload.php'),
            '.env.example is readable' => is_readable($basePath.'/.env.example'),
            'Application directory can create .env' => ! is_file($basePath.'/.env') && is_writable($basePath),
            'storage is writable' => is_dir($basePath.'/storage') && is_writable($basePath.'/storage'),
            'bootstrap/cache is writable' => is_dir($basePath.'/bootstrap/cache') && is_writable($basePath.'/bootstrap/cache'),
            'Installer has not already completed' => ! self::isInstalled($basePath),
        ];

        foreach (self::REQUIRED_EXTENSIONS as $extension) {
            $checks['PHP extension: '.$extension] = extension_loaded($extension);
        }

        $checks['cURL supports CURLOPT_RESOLVE'] = defined('CURLOPT_RESOLVE');

        return $checks;
    }

    /** @param array<string, mixed> $server */
    public static function requestIsHttps(array $server): bool
    {
        $https = strtolower((string) ($server['HTTPS'] ?? ''));

        return ($https !== '' && $https !== 'off') || (string) ($server['SERVER_PORT'] ?? '') === '443';
    }

    /** @param array<string, mixed> $server */
    public static function defaultAppUrl(array $server): string
    {
        $host = trim((string) ($server['HTTP_HOST'] ?? ''));
        if ($host === '') {
            return 'https://gateway.example.com';
        }

        return 'https://'.$host;
    }

    public static function isInstalled(string $basePath): bool
    {
        return is_file(self::installedMarkerPath($basePath));
    }

    public static function installedMarkerPath(string $basePath): string
    {
        return rtrim($basePath, DIRECTORY_SEPARATOR).'/storage/app/private/installed';
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array<string, string>
     */
    public static function validateInput(array $input, string $currentHost): array
    {
        $errors = [];
        $appUrl = trim((string) ($input['app_url'] ?? ''));
        $parts = parse_url($appUrl);

        if (! is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || ! is_string($parts['host'] ?? null)
            || $parts['host'] === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || (isset($parts['path']) && ! in_array($parts['path'], ['', '/'], true))) {
            $errors['app_url'] = 'Application URL must be one canonical HTTPS origin, for example https://gateway.example.com.';
        } elseif ($currentHost !== '' && strtolower($parts['host']) !== strtolower(self::hostWithoutPort($currentHost))) {
            $errors['app_url'] = 'Application URL must use the same hostname as this installer.';
        }

        $dbDriver = strtolower(trim((string) ($input['db_connection'] ?? 'mariadb')));
        if (! in_array($dbDriver, self::SUPPORTED_DATABASE_DRIVERS, true)) {
            $errors['db_connection'] = 'Select MariaDB or MySQL.';
        }

        $dbHost = trim((string) ($input['db_host'] ?? ''));
        if ($dbHost === '' || strlen($dbHost) > 255 || preg_match('/^[A-Za-z0-9._:-]+$/', $dbHost) !== 1) {
            $errors['db_host'] = 'Enter a valid database host.';
        }

        $dbPort = filter_var($input['db_port'] ?? null, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 65535],
        ]);
        if ($dbPort === false) {
            $errors['db_port'] = 'Enter a valid database port.';
        }

        foreach (['db_database' => 'database name', 'db_username' => 'database username'] as $field => $label) {
            $value = trim((string) ($input[$field] ?? ''));
            if ($value === '' || strlen($value) > 64 || preg_match('/^[A-Za-z0-9_$-]+$/', $value) !== 1) {
                $errors[$field] = 'Enter a valid database '.$label.'.';
            }
        }

        if ((string) ($input['db_password'] ?? '') === '') {
            $errors['db_password'] = 'Enter the database password.';
        }

        $adminName = trim((string) ($input['admin_name'] ?? ''));
        if ($adminName === '' || strlen($adminName) > 255) {
            $errors['admin_name'] = 'Enter an administrator name.';
        }

        $adminEmail = strtolower(trim((string) ($input['admin_email'] ?? '')));
        if ($adminEmail === '' || strlen($adminEmail) > 254 || filter_var($adminEmail, FILTER_VALIDATE_EMAIL) === false) {
            $errors['admin_email'] = 'Enter a valid administrator email address.';
        }

        $password = (string) ($input['admin_password'] ?? '');
        $confirmation = (string) ($input['admin_password_confirmation'] ?? '');
        if (strlen($password) < 12
            || preg_match('/[a-z]/', $password) !== 1
            || preg_match('/[A-Z]/', $password) !== 1
            || preg_match('/[0-9]/', $password) !== 1
            || preg_match('/[^A-Za-z0-9]/', $password) !== 1) {
            $errors['admin_password'] = 'Administrator password must be at least 12 characters and include upper/lower case, a number, and a symbol.';
        } elseif (! hash_equals($password, $confirmation)) {
            $errors['admin_password_confirmation'] = 'Administrator password confirmation does not match.';
        }

        return $errors;
    }

    /** @param array<string, mixed> $input */
    public static function install(string $basePath, array $input): void
    {
        $basePath = rtrim($basePath, DIRECTORY_SEPARATOR);
        if (self::isInstalled($basePath)) {
            throw new RuntimeException('MCP Gateway is already installed.');
        }
        if (is_file($basePath.'/.env')) {
            throw new RuntimeException('An .env file already exists. The web installer only runs on a fresh package.');
        }

        self::assertEmptyDatabase($input);

        $template = file_get_contents($basePath.'/.env.example');
        if ($template === false) {
            throw new RuntimeException('Could not read .env.example.');
        }

        $environment = self::buildEnvironment($template, $input, self::generateApplicationKey());
        self::atomicWrite($basePath.'/.env', $environment, 0600);

        try {
            /** @var Application $app */
            $app = require $basePath.'/bootstrap/app.php';
            /** @var ConsoleKernel $kernel */
            $kernel = $app->make(ConsoleKernel::class);
            $kernel->bootstrap();

            self::runConsole($kernel, 'migrate', ['--force' => true], 'Database migrations failed.');
            self::generateSigningKeys($kernel);
            self::runConsole($kernel, 'gateway:check', [], 'Gateway environment validation failed.');

            if (User::query()->exists()) {
                throw new RuntimeException('The selected database already contains an MCP Gateway administrator. Use a new empty database.');
            }

            $markerPath = self::installedMarkerPath($basePath);
            DB::beginTransaction();

            try {
                User::query()->create([
                    'name' => trim((string) $input['admin_name']),
                    'email' => strtolower(trim((string) $input['admin_email'])),
                    'password' => (string) $input['admin_password'],
                    'role' => GatewayRole::Owner->value,
                    'site_scope_mode' => SiteScopeMode::All->value,
                    'access_enabled' => true,
                ]);

                $marker = json_encode([
                    'installed_at' => gmdate(DATE_ATOM),
                    'version' => self::readVersion($basePath),
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                self::atomicWrite($markerPath, $marker."\n", 0600);

                DB::commit();
            } catch (Throwable $exception) {
                DB::rollBack();
                if (is_file($markerPath)) {
                    @unlink($markerPath);
                }

                throw $exception;
            }
        } catch (Throwable $exception) {
            throw new RuntimeException(self::safeFailureMessage($exception), previous: $exception);
        }
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public static function buildEnvironment(string $template, array $input, string $applicationKey): string
    {
        $databaseDriver = strtolower(trim((string) ($input['db_connection'] ?? 'mariadb')));
        if (! in_array($databaseDriver, self::SUPPORTED_DATABASE_DRIVERS, true)) {
            throw new RuntimeException('Unsupported database driver.');
        }

        $values = [
            'APP_ENV' => 'production',
            'APP_KEY' => $applicationKey,
            'APP_DEBUG' => 'false',
            'APP_URL' => rtrim(trim((string) $input['app_url']), '/'),
            'DB_CONNECTION' => $databaseDriver,
            'DB_HOST' => trim((string) $input['db_host']),
            'DB_PORT' => (string) (int) $input['db_port'],
            'DB_DATABASE' => trim((string) $input['db_database']),
            'DB_USERNAME' => trim((string) $input['db_username']),
            'DB_PASSWORD' => (string) $input['db_password'],
            'SESSION_DRIVER' => 'file',
            'SESSION_ENCRYPT' => 'true',
            'SESSION_SECURE_COOKIE' => 'true',
            'SESSION_HTTP_ONLY' => 'true',
            'SESSION_SAME_SITE' => 'lax',
            'CACHE_STORE' => 'file',
            'QUEUE_CONNECTION' => 'sync',
            'FILESYSTEM_DISK' => 'local',
            'MCP_BOOTSTRAP_FIXTURE_ENABLED' => 'false',
            'MCP_BOOTSTRAP_FIXTURE_TOKEN' => '',
        ];

        foreach ($values as $key => $value) {
            $template = self::setEnvValue($template, $key, $value);
        }

        return rtrim($template)."\n";
    }

    public static function generateApplicationKey(): string
    {
        return 'base64:'.base64_encode(random_bytes(32));
    }

    private static function hostWithoutPort(string $host): string
    {
        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');

            return $end === false ? $host : substr($host, 1, $end - 1);
        }

        return explode(':', $host, 2)[0];
    }

    /** @param array<string, mixed> $input */
    private static function assertEmptyDatabase(array $input): void
    {
        // MariaDB and MySQL both use the PDO MySQL transport.
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            trim((string) $input['db_host']),
            (int) $input['db_port'],
            trim((string) $input['db_database']),
        );

        try {
            $pdo = new PDO($dsn, trim((string) $input['db_username']), (string) $input['db_password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 5,
            ]);
            $statement = $pdo->prepare('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = :schema');
            $statement->execute(['schema' => trim((string) $input['db_database'])]);
            if ((int) $statement->fetchColumn() !== 0) {
                throw new RuntimeException('The selected database is not empty. Use a dedicated empty database for MCP Gateway.');
            }
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new RuntimeException('Could not connect to MariaDB/MySQL with the supplied database details.', previous: $exception);
        }
    }

    private static function setEnvValue(string $contents, string $key, string $value): string
    {
        $line = $key.'='.self::quoteEnvValue($value);
        $pattern = '/^'.preg_quote($key, '/').'=.*$/m';

        if (preg_match($pattern, $contents) === 1) {
            $updated = preg_replace($pattern, $line, $contents, 1);

            return is_string($updated) ? $updated : $contents;
        }

        return rtrim($contents)."\n".$line."\n";
    }

    private static function quoteEnvValue(string $value): string
    {
        if ($value === '' || preg_match('/[\s#="\\\\]/', $value) === 1) {
            return '"'.str_replace(['\\', '"', "\n", "\r"], ['\\\\', '\\"', '\\n', '\\r'], $value).'"';
        }

        return $value;
    }

    private static function atomicWrite(string $path, string $contents, int $mode): void
    {
        $directory = dirname($path);
        if (! is_dir($directory) && ! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create a required private directory.');
        }

        $temporary = tempnam($directory, '.mcp-install-');
        if ($temporary === false) {
            throw new RuntimeException('Could not create a temporary installation file.');
        }

        try {
            if (file_put_contents($temporary, $contents, LOCK_EX) === false) {
                throw new RuntimeException('Could not write a required installation file.');
            }
            @chmod($temporary, $mode);
            if (! rename($temporary, $path)) {
                throw new RuntimeException('Could not install a required file atomically.');
            }
            @chmod($path, $mode);
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }

    private static function generateSigningKeys(ConsoleKernel $kernel): void
    {
        $oauthPrivate = (string) config('oauth.keys.private');
        $oauthPublic = (string) config('oauth.keys.public');
        $bridgePrivate = (string) config('bridge.keys.private');
        $bridgePublic = (string) config('bridge.keys.public');

        if (is_file($oauthPrivate) || is_file($oauthPublic) || is_file($bridgePrivate) || is_file($bridgePublic)) {
            throw new RuntimeException('Signing key files already exist. The installer only supports a fresh package.');
        }

        self::runConsole($kernel, 'gateway:oauth-keygen', [], 'Could not generate the Gateway OAuth signing keypair.');
        self::runConsole($kernel, 'gateway:bridge-client-keygen', [], 'Could not generate the Bridge client signing keypair.');
    }

    /** @param array<string, bool|string|int> $arguments */
    private static function runConsole(ConsoleKernel $kernel, string $command, array $arguments, string $failureMessage): void
    {
        if ($kernel->call($command, $arguments) !== 0) {
            throw new RuntimeException($failureMessage);
        }
    }

    private static function readVersion(string $basePath): string
    {
        $version = @file_get_contents($basePath.'/VERSION');

        return $version === false ? 'unknown' : trim($version);
    }

    private static function safeFailureMessage(Throwable $exception): string
    {
        if ($exception instanceof RuntimeException) {
            $message = $exception->getMessage();
            foreach ([
                'Database migrations failed.',
                'Could not generate the Gateway OAuth signing keypair.',
                'Could not generate the Bridge client signing keypair.',
                'Gateway environment validation failed.',
                'The selected database already contains',
                'Signing key files already exist.',
                'Could not create a required',
                'Could not write a required',
                'Could not install a required',
            ] as $safePrefix) {
                if (str_starts_with($message, $safePrefix)) {
                    return $message;
                }
            }
        }

        return 'Installation failed safely. Check PHP/database permissions and the server error log, then retry with a fresh package and empty database.';
    }
}
