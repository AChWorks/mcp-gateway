<?php

declare(strict_types=1);

namespace McpGatewayUpdate;

use Illuminate\Support\Facades\Artisan;
use RuntimeException;
use Throwable;

final class WebUpdater
{
    private const MANAGED_ROOT = [
        '.env.example',
        'LICENSE',
        'VERSION',
        'app',
        'artisan',
        'bootstrap',
        'composer.json',
        'config',
        'database',
        'resources',
        'routes',
        'vendor',
    ];

    private const MANAGED_PUBLIC_PATHS_FILE = 'MANAGED_PUBLIC_PATHS';

    private const BACKUP_MANIFEST_FILE = 'BACKUP_MANIFEST.sha256';

    public function __construct(
        private readonly string $basePath,
        private readonly string $packagePath,
    ) {}

    /** @return array{installed:string,target:string,checks:array<string,bool>} */
    public function inspect(): array
    {
        $this->assertBaseLayout();
        $this->assertPackageIntegrity();

        $installed = $this->readVersion($this->basePath.'/VERSION', 'Installed VERSION');
        $target = $this->readVersion($this->packagePath.'/UPDATE_VERSION', 'UPDATE_VERSION');
        $payloadVersion = $this->readVersion($this->packagePath.'/payload/VERSION', 'Payload VERSION');

        if ($payloadVersion !== $target) {
            throw new RuntimeException('Update metadata and payload version do not match.');
        }

        if (version_compare($installed, $target, '>=')) {
            throw new RuntimeException(sprintf(
                'This package cannot update MCP Gateway %s to %s. The target version must be newer.',
                $installed,
                $target,
            ));
        }

        $checks = [
            'Current installation detected' => true,
            'Update package integrity verified' => true,
            'Private .env will be preserved' => is_file($this->basePath.'/.env'),
            'Persistent storage is available' => is_dir($this->basePath.'/storage/app/private'),
            'Application root is writable' => is_writable($this->basePath),
            'Persistent storage is writable' => is_writable($this->basePath.'/storage/app/private'),
            'Private update staging is writable' => is_writable($this->packagePath),
            'Public directory is writable' => is_writable($this->basePath.'/public'),
            'Temporary public update staging is writable' => is_writable($this->basePath.'/public/update'),
        ];

        $failedChecks = array_keys(array_filter($checks, static fn (bool $passed): bool => ! $passed));
        if ($failedChecks !== []) {
            throw new RuntimeException('Update preflight failed: '.implode('; ', $failedChecks).'.');
        }

        $this->assertManagedMutationPreflight();
        $checks['Gateway-managed paths are replaceable and recoverable'] = true;

        return [
            'installed' => $installed,
            'target' => $target,
            'checks' => $checks,
        ];
    }

    /** @return array{from:string,to:string,continuation:string} */
    public function stage(string $browserToken): array
    {
        $this->assertBrowserToken($browserToken);
        $info = $this->inspect();
        $from = $info['installed'];
        $to = $info['target'];
        $continuation = bin2hex(random_bytes(32));

        $this->runArtisan('gateway:check', ['--no-interaction' => true], 'Current Gateway preflight failed. No files were changed.');

        $backup = $this->createBackup($from, $to);
        try {
            $this->assertBackupCredible($backup, $from, $to);
        } catch (Throwable $exception) {
            try {
                $this->removePath($backup);
            } catch (Throwable) {
            }
            throw $exception;
        }
        try {
            $this->runArtisan('down', ['--retry' => 60, '--no-interaction' => true], 'Could not enter maintenance mode. No application files were changed.');
        } catch (Throwable $exception) {
            try {
                $this->removePath($backup);
            } catch (Throwable) {
            }
            $this->tryResumeApplication();
            throw $exception;
        }

        $filesMutated = false;

        try {
            $this->writeState([
                'from' => $from,
                'to' => $to,
                'backup' => $backup,
                'phase' => 'replace-files',
                'migration_started' => false,
                'browser_token_hash' => hash('sha256', $browserToken),
                'continuation_token' => $continuation,
            ]);

            $filesMutated = true;
            $this->replaceManagedFiles();

            if (! is_file($this->basePath.'/.env')) {
                throw new RuntimeException('Persistent .env disappeared unexpectedly.');
            }
            if (! is_file($this->basePath.'/storage/app/private/installed')) {
                throw new RuntimeException('Installed marker disappeared unexpectedly.');
            }
            $this->assertInstalledRuntimeMatchesPackage($to);

            $this->writeState([
                'from' => $from,
                'to' => $to,
                'backup' => $backup,
                'phase' => 'files-replaced',
                'migration_started' => false,
                'browser_token_hash' => hash('sha256', $browserToken),
                'continuation_token' => $continuation,
            ]);

            return ['from' => $from, 'to' => $to, 'continuation' => $continuation];
        } catch (Throwable $exception) {
            if ($filesMutated && is_string($backup)) {
                try {
                    $this->restoreFiles($backup, $from, $to);
                } catch (Throwable $restoreException) {
                    $this->tryWriteState([
                        'from' => $from,
                        'to' => $to,
                        'backup' => $backup,
                        'phase' => 'failed-before-migration-restore',
                        'migration_started' => false,
                        'browser_token_hash' => hash('sha256', $browserToken),
                        'continuation_token' => $continuation,
                    ]);

                    throw new RuntimeException(
                        'The update failed before database migration and automatic code restore was not safe or could not complete. The application remains in maintenance mode; preserve the updater state and retained private code backup for recovery.',
                        0,
                        $restoreException,
                    );
                }
            } elseif (is_string($backup)) {
                try {
                    $this->removePath($backup);
                } catch (Throwable) {
                }
            }

            @unlink($this->statePath());
            $this->tryResumeApplication();

            throw new RuntimeException(
                $filesMutated
                    ? 'The update failed before database migration. Application files were restored automatically. '.$exception->getMessage()
                    : 'The update failed before application files were changed. The application was returned to service. '.$exception->getMessage(),
                0,
                $exception,
            );
        }
    }

    /** @return array{from:string,to:string,cleanup_warning:?string} */
    public function finish(string $browserToken, string $continuation): array
    {
        $state = $this->readState();
        $this->assertContinuation($state, $browserToken, $continuation);

        $from = $this->requireStateString($state, 'from');
        $to = $this->requireStateString($state, 'to');
        $backup = $this->requireStateString($state, 'backup');
        $phase = $this->requireStateString($state, 'phase');

        if ($phase !== 'files-replaced') {
            throw new RuntimeException('Updater state is not ready for the post-update step.');
        }

        $installed = $this->readVersion($this->basePath.'/VERSION', 'Installed VERSION');
        if ($installed !== $to) {
            throw new RuntimeException('Installed files do not match the expected target version.');
        }

        $migrationStarted = false;
        $backupCredible = false;

        try {
            $this->assertBackupCredible($backup, $from, $to);
            $backupCredible = true;
            $this->assertInstalledRuntimeMatchesPackage($to);
            $this->runArtisan('optimize:clear', ['--no-interaction' => true], 'Cache cleanup failed after file replacement.');

            $state['phase'] = 'migrate';
            $state['migration_started'] = true;
            $this->writeState($state);
            $migrationStarted = true;

            $this->runArtisan('migrate', ['--force' => true, '--no-interaction' => true], 'Database migration failed. The application remains in maintenance mode.');
            $this->runArtisan('gateway:check', ['--no-interaction' => true], 'Post-update Gateway validation failed. The application remains in maintenance mode.');
            $this->runArtisan('up', ['--no-interaction' => true], 'Update completed but maintenance mode could not be cleared automatically.');
        } catch (Throwable $exception) {
            if (! $migrationStarted) {
                if (! $backupCredible) {
                    $state['phase'] = 'failed-before-migration-backup';
                    $state['migration_started'] = false;
                    $this->tryWriteState($state);

                    throw new RuntimeException(
                        'Pre-migration recovery backup failed integrity validation. Database migration did not start and automatic code restore was not attempted. The application remains in maintenance mode; preserve the updater state and retained backup for manual recovery.',
                        0,
                        $exception,
                    );
                }

                try {
                    $this->restoreFiles($backup, $from, $to);
                    @unlink($this->statePath());
                    $this->tryResumeApplication();
                } catch (Throwable $restoreException) {
                    $state['phase'] = 'failed-before-migration-restore';
                    $state['migration_started'] = false;
                    $this->tryWriteState($state);

                    throw new RuntimeException(
                        'The update failed before database migration and automatic code restore was not safe or could not complete. The application remains in maintenance mode; preserve the updater state and retained private code backup for recovery.',
                        0,
                        $restoreException,
                    );
                }

                throw new RuntimeException(
                    'The update failed before database migration. Application files were restored automatically and the application was returned to service. '.$exception->getMessage(),
                    0,
                    $exception,
                );
            }

            $state['phase'] = 'failed-after-migration-start';
            $state['migration_started'] = true;
            $this->tryWriteState($state);

            throw new RuntimeException(
                'The update reached the database-migration boundary and could not finish safely. Automatic code rollback was not attempted. '.$exception->getMessage(),
                0,
                $exception,
            );
        }

        $this->pruneBackups();
        @unlink($this->statePath());
        $cleanupWarning = $this->cleanupUpdater($to);

        return [
            'from' => $from,
            'to' => $to,
            'cleanup_warning' => $cleanupWarning,
        ];
    }

    public function pendingContinuation(string $browserToken): ?string
    {
        if (! is_file($this->statePath())) {
            return null;
        }

        try {
            $state = $this->readState();
            if (($state['phase'] ?? null) !== 'files-replaced' || ! $this->browserTokenMatches($state, $browserToken)) {
                return null;
            }
            $continuation = $state['continuation_token'] ?? null;

            return is_string($continuation) && preg_match('/^[a-f0-9]{64}$/', $continuation) ? $continuation : null;
        } catch (Throwable) {
            return null;
        }
    }

    /** @return array<string,mixed>|null */
    public function failedState(string $browserToken): ?array
    {
        if (! is_file($this->statePath())) {
            return null;
        }

        try {
            $state = $this->readState();
            $phase = $state['phase'] ?? null;
            if (is_string($phase) && str_starts_with($phase, 'failed-') && $this->browserTokenMatches($state, $browserToken)) {
                return $state;
            }
        } catch (Throwable) {
        }

        return null;
    }

    private function assertBaseLayout(): void
    {
        foreach (['.env', 'VERSION', 'artisan', 'vendor/autoload.php', 'storage/app/private/installed'] as $required) {
            if (! file_exists($this->basePath.'/'.$required)) {
                throw new RuntimeException('This directory does not look like an installed MCP Gateway deployment; missing '.$required.'.');
            }
        }

        if (is_dir($this->basePath.'/.git') || is_file($this->basePath.'/composer.lock')) {
            throw new RuntimeException('The browser updater is for deployment-ZIP installations. Use the documented source/Composer path for a source checkout.');
        }

        foreach (array_merge(self::MANAGED_ROOT, ['public', 'storage', 'storage/app', 'storage/app/private']) as $entry) {
            if (is_link($this->basePath.'/'.$entry)) {
                throw new RuntimeException('The installation contains an unsupported symlink: '.$entry.'.');
            }
        }
    }

    private function assertManagedMutationPreflight(): void
    {
        foreach (self::MANAGED_ROOT as $entry) {
            $this->assertManagedRootPathPreflight($this->basePath.'/'.$entry, $entry);
        }

        foreach ($this->managedPublicPaths($this->packagePath.'/'.self::MANAGED_PUBLIC_PATHS_FILE) as $relative) {
            $this->assertManagedPublicPathPreflight($relative);
        }
    }

    private function assertManagedRootPathPreflight(string $path, string $relative): void
    {
        if (is_link($path)) {
            throw new RuntimeException('Gateway-managed path contains an unsupported symlink: '.$relative.'.');
        }
        if (! file_exists($path)) {
            return;
        }
        if (is_file($path)) {
            if (! is_readable($path)) {
                throw new RuntimeException('Gateway-managed file is not readable for backup: '.$relative.'.');
            }
            if (! is_writable(dirname($path))) {
                throw new RuntimeException('Gateway-managed file cannot be replaced because its parent directory is not writable: '.$relative.'.');
            }

            return;
        }
        if (! is_dir($path)) {
            throw new RuntimeException('Gateway-managed path has an unsupported filesystem type: '.$relative.'.');
        }
        if (! is_readable($path) || ! is_writable($path)) {
            throw new RuntimeException('Gateway-managed directory is not readable and writable for backup/replacement: '.$relative.'.');
        }

        $items = scandir($path);
        if ($items === false) {
            throw new RuntimeException('Could not inspect Gateway-managed directory during preflight: '.$relative.'.');
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $childRelative = $relative.'/'.$item;
            $this->assertManagedRootPathPreflight($path.'/'.$item, $childRelative);
        }
    }

    private function assertManagedPublicPathPreflight(string $relative): void
    {
        $public = $this->basePath.'/public';
        $segments = explode('/', $relative);
        $leaf = array_pop($segments);
        $parent = $public;

        foreach ($segments as $segment) {
            $candidate = $parent.'/'.$segment;
            if (is_link($candidate)) {
                throw new RuntimeException('Gateway-managed public path has a symlinked parent: public/'.$relative.'.');
            }
            if (file_exists($candidate) && ! is_dir($candidate)) {
                throw new RuntimeException('Gateway-managed public path has a non-directory parent conflict: public/'.$relative.'.');
            }
            if (is_dir($candidate)) {
                if (! is_readable($candidate) || ! is_writable($candidate)) {
                    throw new RuntimeException('Gateway-managed public path parent is not readable/writable: public/'.$relative.'.');
                }
                $parent = $candidate;

                continue;
            }
            if (! is_writable($parent)) {
                throw new RuntimeException('Gateway-managed public path cannot create its missing parent: public/'.$relative.'.');
            }

            return;
        }

        if (! is_string($leaf) || $leaf === '') {
            throw new RuntimeException('Gateway-managed public path is invalid.');
        }
        $target = $parent.'/'.$leaf;
        if (is_link($target)) {
            throw new RuntimeException('Gateway-managed public path is an unsupported symlink: public/'.$relative.'.');
        }
        if (is_dir($target)) {
            throw new RuntimeException('Gateway-managed public path conflicts with a directory: public/'.$relative.'.');
        }
        if (is_file($target) && ! is_readable($target)) {
            throw new RuntimeException('Gateway-managed public file is not readable for backup: public/'.$relative.'.');
        }
        if (! is_writable($parent)) {
            throw new RuntimeException('Gateway-managed public path cannot be replaced because its parent is not writable: public/'.$relative.'.');
        }
    }

    private function assertPackageIntegrity(): void
    {
        foreach (['UPDATE_VERSION', 'PUBLIC_ENTRY_SHA256', self::MANAGED_PUBLIC_PATHS_FILE, 'manifest.sha256', 'payload', 'WebUpdater.php'] as $required) {
            if (! file_exists($this->packagePath.'/'.$required)) {
                throw new RuntimeException('The extracted update package is incomplete; missing '.$required.'.');
            }
        }

        $expectedPackageTop = ['PUBLIC_ENTRY_SHA256', 'UPDATE_VERSION', self::MANAGED_PUBLIC_PATHS_FILE, 'WebUpdater.php', 'manifest.sha256', 'payload'];
        $actualPackageTop = $this->directoryNames($this->packagePath);
        sort($expectedPackageTop);
        sort($actualPackageTop);
        if ($actualPackageTop !== $expectedPackageTop) {
            throw new RuntimeException('The private update staging directory contains unexpected files. Remove or rename the conflicting root update directory and re-extract the named update ZIP.');
        }

        $expectedPublicTop = ['index.php'];
        $actualPublicTop = $this->directoryNames($this->basePath.'/public/update');
        if ($actualPublicTop !== $expectedPublicTop) {
            throw new RuntimeException('The temporary public update directory contains unexpected files. Remove or rename the conflicting public/update directory and re-extract the named update ZIP.');
        }

        if ($this->containsSymlink($this->packagePath)) {
            throw new RuntimeException('The update package contains a symbolic link and was rejected.');
        }

        $expectedEntryHash = trim((string) file_get_contents($this->packagePath.'/PUBLIC_ENTRY_SHA256'));
        $entryPath = $this->basePath.'/public/update/index.php';
        $actualEntryHash = is_file($entryPath) ? hash_file('sha256', $entryPath) : false;
        if (! preg_match('/^[a-f0-9]{64}$/', $expectedEntryHash) || ! is_string($actualEntryHash) || ! hash_equals($expectedEntryHash, $actualEntryHash)) {
            throw new RuntimeException('Temporary public updater integrity check failed. Re-extract the named update ZIP.');
        }

        $expectedTop = [
            '.env.example', 'LICENSE', 'VERSION', 'app', 'artisan', 'bootstrap', 'composer.json',
            'config', 'database', 'public', 'resources', 'routes', 'vendor',
        ];
        $actualTop = $this->directoryNames($this->packagePath.'/payload');
        sort($expectedTop);
        sort($actualTop);
        if ($actualTop !== $expectedTop) {
            throw new RuntimeException('Update payload layout is invalid.');
        }
        if (file_exists($this->packagePath.'/payload/.env') || file_exists($this->packagePath.'/payload/storage')) {
            throw new RuntimeException('Update payload must not contain production .env or persistent storage.');
        }
        if (! is_file($this->packagePath.'/payload/vendor/autoload.php')) {
            throw new RuntimeException('Update payload is missing production Composer dependencies.');
        }

        $lines = file($this->packagePath.'/manifest.sha256', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false || $lines === []) {
            throw new RuntimeException('Update manifest is empty or unreadable.');
        }

        $seen = [];
        foreach ($lines as $line) {
            if (! preg_match('/^([a-f0-9]{64})  (.+)$/', $line, $match)) {
                throw new RuntimeException('Update manifest contains an invalid entry.');
            }
            $relative = $match[2];
            if (! $this->safeRelativePath($relative) || isset($seen[$relative])) {
                throw new RuntimeException('Update manifest contains an unsafe or duplicate path.');
            }
            $full = $this->packagePath.'/'.$relative;
            if (! is_file($full) || is_link($full)) {
                throw new RuntimeException('Update manifest references a missing or invalid file: '.$relative.'.');
            }
            $actual = hash_file('sha256', $full);
            if (! is_string($actual) || ! hash_equals($match[1], $actual)) {
                throw new RuntimeException('Update package checksum validation failed. Re-download the named update ZIP.');
            }
            $seen[$relative] = true;
        }

        $managedPublicPaths = $this->managedPublicPaths($this->packagePath.'/'.self::MANAGED_PUBLIC_PATHS_FILE);
        $managedPublicLookup = array_fill_keys($managedPublicPaths, true);
        foreach ($this->recursiveFiles($this->packagePath.'/payload/public', '') as $relative) {
            $publicPath = ltrim($relative, '/');
            if (! isset($managedPublicLookup[$publicPath])) {
                throw new RuntimeException('Update payload contains a public file outside the Gateway-owned manifest: public/'.$publicPath.'.');
            }
        }

        $requiredManifest = ['PUBLIC_ENTRY_SHA256', 'UPDATE_VERSION', self::MANAGED_PUBLIC_PATHS_FILE, 'WebUpdater.php'];
        foreach ($this->recursiveFiles($this->packagePath.'/payload', 'payload') as $relative) {
            $requiredManifest[] = $relative;
        }
        sort($requiredManifest);
        $actualManifest = array_keys($seen);
        sort($actualManifest);
        if ($requiredManifest !== $actualManifest) {
            throw new RuntimeException('Update manifest does not exactly cover the package payload.');
        }
    }

    private function assertBackupCredible(string $backup, string $from, string $to): void
    {
        $expectedTop = [
            self::BACKUP_MANIFEST_FILE,
            self::MANAGED_PUBLIC_PATHS_FILE,
            'FROM_VERSION',
            'TO_VERSION',
            'files',
        ];
        $actualTop = $this->directoryNames($backup);
        sort($expectedTop);
        sort($actualTop);
        if ($actualTop !== $expectedTop || is_link($backup.'/files')) {
            throw new RuntimeException('Pre-migration recovery backup layout is incomplete or unexpected.');
        }

        foreach ([self::BACKUP_MANIFEST_FILE, self::MANAGED_PUBLIC_PATHS_FILE, 'FROM_VERSION', 'TO_VERSION'] as $requiredFile) {
            if (! is_file($backup.'/'.$requiredFile) || is_link($backup.'/'.$requiredFile)) {
                throw new RuntimeException('Pre-migration recovery backup is incomplete.');
            }
        }
        if (! is_dir($backup.'/files') || ! is_file($backup.'/files/VERSION')) {
            throw new RuntimeException('Pre-migration recovery backup is incomplete.');
        }

        $manifestLines = file($backup.'/'.self::BACKUP_MANIFEST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($manifestLines === false || $manifestLines === []) {
            throw new RuntimeException('Pre-migration recovery backup integrity manifest is empty or unreadable.');
        }

        $seen = [];
        foreach ($manifestLines as $line) {
            if (! preg_match('/^([a-f0-9]{64})  (.+)$/', $line, $match)) {
                throw new RuntimeException('Pre-migration recovery backup integrity manifest contains an invalid entry.');
            }
            $relative = $match[2];
            if (! $this->safeRelativePath($relative)
                || $relative === self::BACKUP_MANIFEST_FILE
                || isset($seen[$relative])) {
                throw new RuntimeException('Pre-migration recovery backup integrity manifest contains an unsafe or duplicate path.');
            }
            $full = $backup.'/'.$relative;
            if (! is_file($full) || is_link($full)) {
                throw new RuntimeException('Pre-migration recovery backup file is missing or invalid: '.$relative.'.');
            }
            $actual = hash_file('sha256', $full);
            if (! is_string($actual) || ! hash_equals($match[1], $actual)) {
                throw new RuntimeException('Pre-migration recovery backup checksum validation failed: '.$relative.'.');
            }
            $seen[$relative] = true;
        }

        $requiredManifest = ['FROM_VERSION', 'TO_VERSION', self::MANAGED_PUBLIC_PATHS_FILE];
        foreach ($this->recursiveFiles($backup.'/files', 'files') as $relative) {
            $requiredManifest[] = $relative;
        }
        sort($requiredManifest);
        $actualManifest = array_keys($seen);
        sort($actualManifest);
        if ($requiredManifest !== $actualManifest) {
            throw new RuntimeException('Pre-migration recovery backup integrity manifest does not exactly cover the recovery set.');
        }

        if ($this->readVersion($backup.'/FROM_VERSION', 'Backup FROM_VERSION') !== $from
            || $this->readVersion($backup.'/TO_VERSION', 'Backup TO_VERSION') !== $to
            || $this->readVersion($backup.'/files/VERSION', 'Backup installed VERSION') !== $from) {
            throw new RuntimeException('Pre-migration recovery backup identity does not match the update.');
        }

        $backupPublicPaths = $this->managedPublicPaths($backup.'/'.self::MANAGED_PUBLIC_PATHS_FILE);
        $packagePublicPaths = $this->managedPublicPaths($this->packagePath.'/'.self::MANAGED_PUBLIC_PATHS_FILE);
        if ($backupPublicPaths !== $packagePublicPaths) {
            throw new RuntimeException('Pre-migration recovery backup public ownership manifest does not match the update.');
        }

        if (is_dir($backup.'/files/public')) {
            $allowed = array_fill_keys($backupPublicPaths, true);
            foreach ($this->recursiveFiles($backup.'/files/public', '') as $relative) {
                $publicPath = ltrim($relative, '/');
                if (! isset($allowed[$publicPath])) {
                    throw new RuntimeException('Pre-migration recovery backup contains an unexpected public path: public/'.$publicPath.'.');
                }
            }
        }
    }

    private function assertInstalledRuntimeMatchesPackage(string $targetVersion): void
    {
        if ($this->readVersion($this->basePath.'/VERSION', 'Installed VERSION') !== $targetVersion) {
            throw new RuntimeException('Installed managed runtime version does not match the update target.');
        }

        $lines = file($this->packagePath.'/manifest.sha256', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false || $lines === []) {
            throw new RuntimeException('Update manifest is unavailable while verifying the installed managed runtime.');
        }

        foreach ($lines as $line) {
            if (! preg_match('/^([a-f0-9]{64})  payload\/(.+)$/', $line, $match)) {
                continue;
            }

            $relative = $match[2];
            $target = str_starts_with($relative, 'public/')
                ? $this->basePath.'/public/'.substr($relative, strlen('public/'))
                : $this->basePath.'/'.$relative;

            if (! is_file($target) || is_link($target)) {
                throw new RuntimeException('Installed managed runtime path is missing or invalid: '.$relative.'.');
            }
            $actual = hash_file('sha256', $target);
            if (! is_string($actual) || ! hash_equals($match[1], $actual)) {
                throw new RuntimeException('Installed managed runtime path does not match the verified payload: '.$relative.'.');
            }
        }
    }

    private function replaceManagedFiles(): void
    {
        foreach (self::MANAGED_ROOT as $entry) {
            $target = $this->basePath.'/'.$entry;
            $this->removePath($target);
            $this->copyPath($this->packagePath.'/payload/'.$entry, $target);
        }

        $this->replaceManagedPublicFiles();
    }

    private function replaceManagedPublicFiles(): void
    {
        if (! is_dir($this->basePath.'/public/update')) {
            throw new RuntimeException('Temporary public updater disappeared before file replacement.');
        }

        foreach ($this->managedPublicPaths($this->packagePath.'/'.self::MANAGED_PUBLIC_PATHS_FILE) as $relative) {
            $target = $this->basePath.'/public/'.$relative;
            $source = $this->packagePath.'/payload/public/'.$relative;

            if (is_dir($target) && ! is_link($target)) {
                throw new RuntimeException('Gateway-managed public path conflicts with a directory: public/'.$relative.'.');
            }

            if (file_exists($target) || is_link($target)) {
                try {
                    $this->removePath($target);
                } catch (Throwable $exception) {
                    throw new RuntimeException('Could not replace Gateway-managed public path: public/'.$relative.'.', 0, $exception);
                }
            }

            if (is_file($source)) {
                $this->copyPath($source, $target);
            }
        }
    }

    private function createBackup(string $from, string $to): string
    {
        $backupBase = $this->basePath.'/storage/app/private/update-backups';
        if (! is_dir($backupBase) && ! mkdir($backupBase, 0700, true) && ! is_dir($backupBase)) {
            throw new RuntimeException('Could not create the updater backup directory.');
        }

        $backup = $backupBase.'/'.gmdate('Ymd\\THis\\Z').'-'.bin2hex(random_bytes(4)).'-'.$from.'-to-'.$to;
        if (! mkdir($backup.'/files', 0700, true) && ! is_dir($backup.'/files')) {
            throw new RuntimeException('Could not create the updater code backup.');
        }

        try {
            foreach (self::MANAGED_ROOT as $entry) {
                $source = $this->basePath.'/'.$entry;
                if (file_exists($source) || is_link($source)) {
                    $this->copyPath($source, $backup.'/files/'.$entry);
                }
            }

            $managedPublicPaths = $this->managedPublicPaths($this->packagePath.'/'.self::MANAGED_PUBLIC_PATHS_FILE);
            foreach ($managedPublicPaths as $relative) {
                $source = $this->basePath.'/public/'.$relative;
                if (is_dir($source) && ! is_link($source)) {
                    throw new RuntimeException('Gateway-managed public path conflicts with a directory while creating backup: public/'.$relative.'.');
                }
                if (file_exists($source) || is_link($source)) {
                    $this->copyPath($source, $backup.'/files/public/'.$relative);
                }
            }

            if (file_put_contents($backup.'/'.self::MANAGED_PUBLIC_PATHS_FILE, implode("\n", $managedPublicPaths)."\n", LOCK_EX) === false
                || file_put_contents($backup.'/FROM_VERSION', $from."\n", LOCK_EX) === false
                || file_put_contents($backup.'/TO_VERSION', $to."\n", LOCK_EX) === false) {
                throw new RuntimeException('Could not finalize updater backup metadata.');
            }

            $manifestPaths = ['FROM_VERSION', 'TO_VERSION', self::MANAGED_PUBLIC_PATHS_FILE];
            foreach ($this->recursiveFiles($backup.'/files', 'files') as $relative) {
                $manifestPaths[] = $relative;
            }
            sort($manifestPaths, SORT_STRING);

            $manifestLines = [];
            foreach ($manifestPaths as $relative) {
                $full = $backup.'/'.$relative;
                if (! is_file($full) || is_link($full)) {
                    throw new RuntimeException('Could not finalize updater backup integrity manifest; invalid recovery path: '.$relative.'.');
                }
                $hash = hash_file('sha256', $full);
                if (! is_string($hash)) {
                    throw new RuntimeException('Could not hash updater backup recovery path: '.$relative.'.');
                }
                $manifestLines[] = $hash.'  '.$relative;
            }
            if (file_put_contents($backup.'/'.self::BACKUP_MANIFEST_FILE, implode("\n", $manifestLines)."\n", LOCK_EX) === false) {
                throw new RuntimeException('Could not finalize updater backup integrity manifest.');
            }
        } catch (Throwable $exception) {
            $this->removePath($backup);
            throw $exception;
        }

        return $backup;
    }

    private function restoreFiles(string $backup, string $from, string $to): void
    {
        $this->assertBackupCredible($backup, $from, $to);
        $managedPublicPaths = $this->managedPublicPaths($backup.'/'.self::MANAGED_PUBLIC_PATHS_FILE);

        foreach (self::MANAGED_ROOT as $entry) {
            $this->removePath($this->basePath.'/'.$entry);
            if (file_exists($backup.'/files/'.$entry)) {
                $this->copyPath($backup.'/files/'.$entry, $this->basePath.'/'.$entry);
            }
        }

        foreach ($managedPublicPaths as $relative) {
            $target = $this->basePath.'/public/'.$relative;
            $source = $backup.'/files/public/'.$relative;

            if (is_dir($target) && ! is_link($target)) {
                throw new RuntimeException('Gateway-managed public path conflicts with a directory during restore: public/'.$relative.'.');
            }

            if (file_exists($target) || is_link($target)) {
                try {
                    $this->removePath($target);
                } catch (Throwable $exception) {
                    throw new RuntimeException('Could not restore Gateway-managed public path: public/'.$relative.'.', 0, $exception);
                }
            }

            if (is_file($source)) {
                $this->copyPath($source, $target);
            }
        }
    }

    private function cleanupUpdater(string $version): ?string
    {
        $warning = null;
        $canonicalZip = $this->basePath.'/mcp-gateway-update-v'.$version.'.zip';

        foreach ([$canonicalZip, $canonicalZip.'.sha256'] as $file) {
            if (is_file($file) && ! @unlink($file)) {
                $warning = 'Update completed, but the uploaded release ZIP/checksum could not be removed automatically.';
            }
        }

        try {
            $this->removePath($this->packagePath);
        } catch (Throwable) {
            $warning = 'Update completed, but the private update staging directory could not be removed automatically.';
        }
        try {
            $this->removePath($this->basePath.'/public/update');
        } catch (Throwable) {
            $warning = 'Update completed, but the temporary /update/ endpoint could not be removed automatically. It is locked by the installed-version check and should be removed manually.';
        }

        return $warning;
    }

    private function pruneBackups(): void
    {
        $base = $this->basePath.'/storage/app/private/update-backups';
        if (! is_dir($base)) {
            return;
        }

        $scan = scandir($base);
        $entries = $scan === false ? [] : array_values(array_filter($scan, static fn (string $name): bool => $name !== '.' && $name !== '..' && is_dir($base.'/'.$name)));
        rsort($entries, SORT_STRING);
        foreach (array_slice($entries, 3) as $name) {
            $this->removePath($base.'/'.$name);
        }
    }

    /** @param array<string,mixed> $parameters */
    private function runArtisan(string $command, array $parameters, string $failure): void
    {
        try {
            $exit = Artisan::call($command, $parameters);
        } catch (Throwable $exception) {
            throw new RuntimeException($failure, 0, $exception);
        }

        if ($exit !== 0) {
            throw new RuntimeException($failure);
        }
    }

    private function tryResumeApplication(): void
    {
        try {
            Artisan::call('up', ['--no-interaction' => true]);
        } catch (Throwable) {
        }
    }

    /** @param array<string,mixed> $state */
    private function writeState(array $state): void
    {
        $encoded = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (file_put_contents($this->statePath(), $encoded."\n", LOCK_EX) === false) {
            throw new RuntimeException('Could not persist updater state.');
        }
        @chmod($this->statePath(), 0600);
    }

    /** @param array<string,mixed> $state */
    private function tryWriteState(array $state): void
    {
        try {
            $this->writeState($state);
        } catch (Throwable) {
        }
    }

    /** @return array<string,mixed> */
    private function readState(): array
    {
        $raw = file_get_contents($this->statePath());
        if (! is_string($raw)) {
            throw new RuntimeException('Updater state is missing or unreadable.');
        }
        $state = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($state)) {
            throw new RuntimeException('Updater state is invalid.');
        }

        return $state;
    }

    private function statePath(): string
    {
        return $this->basePath.'/storage/app/private/update-state.json';
    }

    /** @param array<string,mixed> $state */
    private function assertContinuation(array $state, string $browserToken, string $continuation): void
    {
        if (! $this->browserTokenMatches($state, $browserToken)) {
            throw new RuntimeException('The browser update session is invalid or expired.');
        }
        $expected = $state['continuation_token'] ?? null;
        if (! is_string($expected) || ! preg_match('/^[a-f0-9]{64}$/', $expected) || ! hash_equals($expected, $continuation)) {
            throw new RuntimeException('The update continuation token is invalid or expired.');
        }
    }

    /** @param array<string,mixed> $state */
    private function browserTokenMatches(array $state, string $browserToken): bool
    {
        if (! preg_match('/^[a-f0-9]{64}$/', $browserToken)) {
            return false;
        }
        $expected = $state['browser_token_hash'] ?? null;

        return is_string($expected) && preg_match('/^[a-f0-9]{64}$/', $expected) && hash_equals($expected, hash('sha256', $browserToken));
    }

    private function assertBrowserToken(string $browserToken): void
    {
        if (! preg_match('/^[a-f0-9]{64}$/', $browserToken)) {
            throw new RuntimeException('The browser update session is invalid. Reload /update/ and try again.');
        }
    }

    /** @param array<string,mixed> $state */
    private function requireStateString(array $state, string $key): string
    {
        $value = $state[$key] ?? null;
        if (! is_string($value) || $value === '') {
            throw new RuntimeException('Updater state is missing '.$key.'.');
        }

        return $value;
    }

    private function readVersion(string $path, string $label): string
    {
        $raw = @file_get_contents($path);
        $version = is_string($raw) ? trim($raw) : '';
        if (! preg_match('/^\d+\.\d+\.\d+$/', $version)) {
            throw new RuntimeException($label.' is invalid.');
        }

        return $version;
    }

    private function containsSymlink(string $path): bool
    {
        if (is_link($path)) {
            return true;
        }
        if (! is_dir($path)) {
            return false;
        }
        $items = scandir($path);
        if ($items === false) {
            throw new RuntimeException('Could not inspect update package paths.');
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            if ($this->containsSymlink($path.'/'.$item)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    private function directoryNames(string $path): array
    {
        $items = scandir($path);
        if ($items === false) {
            throw new RuntimeException('Could not inspect update payload layout.');
        }

        return array_values(array_filter($items, static fn (string $item): bool => $item !== '.' && $item !== '..'));
    }

    /** @return list<string> */
    private function recursiveFiles(string $root, string $prefix): array
    {
        $files = [];
        $walk = function (string $dir, string $relative) use (&$walk, &$files): void {
            $items = scandir($dir);
            if ($items === false) {
                throw new RuntimeException('Could not inspect update payload files.');
            }
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
                $full = $dir.'/'.$item;
                $rel = $relative.'/'.$item;
                if (is_link($full)) {
                    throw new RuntimeException('Update package contains a symbolic link.');
                }
                if (is_dir($full)) {
                    $walk($full, $rel);
                } elseif (is_file($full)) {
                    $files[] = $rel;
                }
            }
        };
        $walk($root, $prefix);

        return $files;
    }

    private function safeRelativePath(string $path): bool
    {
        return $path !== ''
            && ! str_starts_with($path, '/')
            && ! str_contains($path, '\\')
            && ! preg_match('#(^|/)\.\.(/|$)#', $path)
            && ! str_contains($path, "\0");
    }

    /** @return list<string> */
    private function managedPublicPaths(string $manifestPath): array
    {
        $lines = file($manifestPath, FILE_IGNORE_NEW_LINES);
        if ($lines === false || $lines === []) {
            throw new RuntimeException('Gateway-managed public path manifest is empty or unreadable.');
        }

        $paths = [];
        $seen = [];
        foreach ($lines as $line) {
            if ($line === ''
                || trim($line) !== $line
                || ! preg_match('#^[A-Za-z0-9._/-]+$#', $line)
                || ! $this->safeRelativePath($line)
                || str_ends_with($line, '/')
                || $line === 'update'
                || str_starts_with($line, 'update/')
                || isset($seen[$line])) {
                throw new RuntimeException('Gateway-managed public path manifest contains an unsafe, blank, or duplicate entry.');
            }
            $seen[$line] = true;
            $paths[] = $line;
        }

        sort($paths, SORT_STRING);

        return $paths;
    }

    /** @param list<string> $excludeNames */
    private function copyPath(string $source, string $target, array $excludeNames = []): void
    {
        if (is_link($source)) {
            throw new RuntimeException('Refusing to copy a symbolic link.');
        }
        if (is_file($source)) {
            $parent = dirname($target);
            if (! is_dir($parent) && ! mkdir($parent, 0755, true) && ! is_dir($parent)) {
                throw new RuntimeException('Could not create destination directory: '.$parent.'.');
            }
            if (! copy($source, $target)) {
                throw new RuntimeException('Could not copy update file to: '.$target.'.');
            }

            return;
        }
        if (! is_dir($source)) {
            throw new RuntimeException('Update source path is missing: '.$source.'.');
        }
        if (! is_dir($target) && ! mkdir($target, 0755, true) && ! is_dir($target)) {
            throw new RuntimeException('Could not create update destination directory: '.$target.'.');
        }
        $items = scandir($source);
        if ($items === false) {
            throw new RuntimeException('Could not enumerate update source directory.');
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || in_array($item, $excludeNames, true)) {
                continue;
            }
            $this->copyPath($source.'/'.$item, $target.'/'.$item);
        }
    }

    private function removePath(string $path): void
    {
        if (! file_exists($path) && ! is_link($path)) {
            return;
        }
        if (is_link($path) || is_file($path)) {
            if (! @unlink($path)) {
                throw new RuntimeException('Could not remove path: '.$path.'.');
            }

            return;
        }
        $items = scandir($path);
        if ($items === false) {
            throw new RuntimeException('Could not enumerate path for removal: '.$path.'.');
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $this->removePath($path.'/'.$item);
        }
        if (! @rmdir($path)) {
            throw new RuntimeException('Could not remove directory: '.$path.'.');
        }
    }
}
