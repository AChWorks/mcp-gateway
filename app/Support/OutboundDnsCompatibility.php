<?php

namespace App\Support;

/**
 * Lightweight in-process PHP file accessibility preflight for React DNS.
 * This is NOT proof that DNS, remote HTTPS or OAuth will succeed.
 */
final class OutboundDnsCompatibility
{
    /**
     * @param  callable(string):bool|null  $readable  Allows deterministic tests.
     * @return array{applicable:bool,open_basedir_active:bool,resolv_conf_readable:bool,hosts_readable:bool,ready:bool}
     */
    public static function snapshot(?callable $readable = null, ?string $platform = null, ?string $openBasedir = null): array
    {
        $readable ??= static fn (string $path): bool => @is_readable($path);
        $platform ??= PHP_OS_FAMILY;
        $openBasedir ??= (string) ini_get('open_basedir');
        $applicable = $platform !== 'Windows';
        $resolv = $applicable && $readable('/etc/resolv.conf');
        $hosts = $applicable && $readable('/etc/hosts');

        return [
            'applicable' => $applicable,
            'open_basedir_active' => $openBasedir !== '',
            'resolv_conf_readable' => $resolv,
            'hosts_readable' => $hosts,
            'ready' => $applicable && $resolv && $hosts,
        ];
    }
}
