#!/usr/bin/env php
<?php

use Composer\InstalledVersions;

function fail(string $message): never
{
    fwrite(STDERR, $message."\n");
    exit(1);
}

function normalizeRelativePath(string $path): ?string
{
    $path = str_replace('\\', '/', trim($path));
    $path = preg_replace('#^\./#', '', $path) ?? $path;
    $path = trim($path, '/');

    if ($path === '' || $path === '.' || str_contains($path, '..') || str_starts_with($path, '/')) {
        return null;
    }

    return $path;
}

function removePath(string $path): void
{
    if (is_link($path) || is_file($path)) {
        if (! @unlink($path) && (is_link($path) || is_file($path))) {
            fail('Could not remove file: '.$path);
        }

        return;
    }

    if (! is_dir($path)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        $itemPath = $item->getPathname();
        if ($item->isDir() && ! $item->isLink()) {
            if (! @rmdir($itemPath) && is_dir($itemPath)) {
                fail('Could not remove directory: '.$itemPath);
            }
        } elseif (! @unlink($itemPath) && (is_file($itemPath) || is_link($itemPath))) {
            fail('Could not remove file: '.$itemPath);
        }
    }

    if (! @rmdir($path) && is_dir($path)) {
        fail('Could not remove directory: '.$path);
    }
}

function directoryBytes(string $path): int
{
    $bytes = 0;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $item) {
        if ($item->isFile() && ! $item->isLink()) {
            $bytes += $item->getSize();
        }
    }

    return $bytes;
}

/** @return list<string> */
function autoloadDevPaths(array $composer): array
{
    $paths = [];
    $autoloadDev = $composer['autoload-dev'] ?? [];

    foreach (['psr-4', 'psr-0'] as $type) {
        foreach (($autoloadDev[$type] ?? []) as $value) {
            foreach ((array) $value as $path) {
                $normalized = normalizeRelativePath((string) $path);
                if ($normalized !== null) {
                    $paths[] = $normalized;
                }
            }
        }
    }

    foreach (['classmap', 'files'] as $type) {
        foreach (($autoloadDev[$type] ?? []) as $path) {
            $normalized = normalizeRelativePath((string) $path);
            if ($normalized !== null) {
                $paths[] = $normalized;
            }
        }
    }

    return array_values(array_unique($paths));
}

/** @return list<array{path: string, reason: string}> */
function collectCandidates(string $vendor): array
{
    $candidates = [];

    $add = static function (string $path, string $reason) use (&$candidates): void {
        if (is_file($path) || is_dir($path) || is_link($path)) {
            $candidates[$path] = ['path' => $path, 'reason' => $reason];
        }
    };

    $add($vendor.'/bin', 'Composer binary proxies are not application runtime files');
    $add($vendor.'/composer/installed.json', 'Composer install metadata JSON is not required at runtime; installed.php remains');

    foreach (glob($vendor.'/*/*/composer.json') ?: [] as $manifest) {
        $packageRoot = dirname($manifest);
        $composer = json_decode((string) file_get_contents($manifest), true);
        if (! is_array($composer)) {
            fail('Invalid package composer.json: '.$manifest);
        }

        foreach (['.github', '.gitlab', '.circleci'] as $directory) {
            $add($packageRoot.'/'.$directory, 'repository/CI metadata');
        }

        foreach (['docs', 'doc', 'examples', 'example', 'benchmarks', 'benchmark'] as $directory) {
            $add($packageRoot.'/'.$directory, 'package documentation/example/benchmark material');
        }

        foreach (autoloadDevPaths($composer) as $relativePath) {
            $add($packageRoot.'/'.$relativePath, 'package autoload-dev material');
        }

        foreach ((array) ($composer['autoload']['exclude-from-classmap'] ?? []) as $excludedPath) {
            $relativePath = normalizeRelativePath((string) $excludedPath);
            if ($relativePath === null) {
                continue;
            }

            $firstSegment = strtolower(strtok($relativePath, '/') ?: '');
            if (in_array($firstSegment, ['test', 'tests'], true)) {
                $add($packageRoot.'/'.$relativePath, 'package-declared test tree excluded from production classmap');
            }
        }

        foreach (scandir($packageRoot) ?: [] as $name) {
            $path = $packageRoot.'/'.$name;
            if (! is_file($path)) {
                continue;
            }

            $isDocumentation = preg_match(
                '/^(README|CHANGELOG|CHANGES|CONTRIBUTING|UPGRAD(?:E|ING)|SECURITY|CODE_OF_CONDUCT|TODO)(\..*)?$/i',
                $name,
            ) === 1;
            $isDevelopmentConfig = preg_match(
                '/^(phpunit\.xml|phpstan\.neon|psalm\.xml|infection\.json|phpcs\.xml)(\..*)?$/i',
                $name,
            ) === 1;

            if ($isDocumentation || $isDevelopmentConfig || in_array($name, [
                '.editorconfig',
                '.gitattributes',
                '.gitignore',
                '.travis.yml',
                'Makefile',
                'box.json',
            ], true)) {
                $add($path, $isDocumentation ? 'package documentation' : 'package development/build metadata');
            }
        }

        foreach ([
            'dist/Makefile',
            'dist/box.json',
            'dist/phar-testing-autoload.php',
        ] as $relativePath) {
            $add($packageRoot.'/'.$relativePath, 'package distribution/build artifact');
        }

        foreach ([
            'dist/signingkey*.asc',
            'dist/signingkey*.asc.sig',
            'dist/*.phar.pubkey',
            'dist/*.phar.pubkey.asc',
        ] as $pattern) {
            foreach (glob($packageRoot.'/'.$pattern) ?: [] as $path) {
                $add($path, 'package distribution signing artifact');
            }
        }
    }

    ksort($candidates);

    return array_values($candidates);
}

$args = $argv;
array_shift($args);
$checkOnly = false;

if (($args[0] ?? null) === '--check') {
    $checkOnly = true;
    array_shift($args);
}

if (count($args) !== 1) {
    fail('Usage: php bin/prune-production-vendor.php [--check] <vendor-directory>');
}

$vendor = realpath($args[0]);
if ($vendor === false || ! is_dir($vendor) || ! is_file($vendor.'/autoload.php') || ! is_file($vendor.'/composer/installed.php')) {
    fail('Invalid production vendor directory: '.$args[0]);
}

$candidates = collectCandidates($vendor);

if ($checkOnly) {
    if ($candidates !== []) {
        fwrite(STDERR, "Production vendor still contains removable non-runtime material:\n");
        foreach ($candidates as $candidate) {
            fwrite(STDERR, '- '.substr($candidate['path'], strlen($vendor) + 1).' ['.$candidate['reason']."]\n");
        }
        exit(1);
    }

    echo "Production vendor hygiene check passed.\n";
    exit(0);
}

$before = directoryBytes($vendor);
foreach ($candidates as $candidate) {
    removePath($candidate['path']);
}

$remaining = collectCandidates($vendor);
if ($remaining !== []) {
    fail('Production vendor pruning was incomplete.');
}

require $vendor.'/autoload.php';

if (! class_exists(InstalledVersions::class)
    || InstalledVersions::getPrettyVersion('laravel/framework') === null
    || InstalledVersions::getPrettyVersion('mcp/sdk') === null) {
    fail('Composer runtime metadata is incomplete after vendor pruning.');
}

$after = directoryBytes($vendor);
printf(
    "Production vendor pruned: %d paths removed, %d bytes removed.\n",
    count($candidates),
    max(0, $before - $after),
);
