<?php

namespace Tests\Unit\Support;

use App\Support\OutboundDnsCompatibility;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class OutboundDnsCompatibilityTest extends TestCase
{
    #[DataProvider('readabilityCases')]
    public function test_php_resolver_file_readability_is_separate_from_open_basedir_and_network(
        bool $resolv,
        bool $hosts,
        string $basedir,
        bool $ready,
    ): void {
        $observed = [];
        $snapshot = OutboundDnsCompatibility::snapshot(
            static function (string $path) use (&$observed, $resolv, $hosts): bool {
                $observed[] = $path;

                return $path === '/etc/resolv.conf' ? $resolv : $hosts;
            },
            'Linux', $basedir,
        );

        self::assertSame(['/etc/resolv.conf', '/etc/hosts'], $observed);
        self::assertSame($resolv, $snapshot['resolv_conf_readable']);
        self::assertSame($hosts, $snapshot['hosts_readable']);
        self::assertSame($basedir !== '', $snapshot['open_basedir_active']);
        self::assertSame($ready, $snapshot['ready']);
    }

    /** @return iterable<string, array{bool,bool,string,bool}> */
    public static function readabilityCases(): iterable
    {
        yield 'ready without basedir' => [true, true, '', true];
        yield 'ready with narrow approved allowlist' => [true, true, '/app:/etc', true];
        yield 'resolv restricted' => [false, true, '/app', false];
        yield 'hosts restricted' => [true, false, '/app', false];
    }

    public function test_windows_skips_linux_specific_file_checks(): void
    {
        $snapshot = OutboundDnsCompatibility::snapshot(
            static function (): never {
                throw new \RuntimeException('Should not read Linux files on Windows');
            },
            'Windows', '',
        );
        self::assertFalse($snapshot['applicable']);
        self::assertFalse($snapshot['ready']);
    }
}
