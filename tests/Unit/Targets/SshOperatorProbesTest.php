<?php

namespace Tests\Unit\Targets;

use App\Application\Targets\SshOperatorProbes;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SshOperatorProbesTest extends TestCase
{
    public function test_each_system_section_has_its_own_source_exit_and_partial_state(): void
    {
        $raw = "__GW_SECTION__:uptime\n123.45 678\n__GW_EXIT__:0\n"
            ."__GW_SECTION__:listeners\nss: not found\n__GW_EXIT__:127\n"
            ."__GW_SECTION__:memory\nMemTotal: 1000 kB\n";

        $normal = SshOperatorProbes::parseSystem($raw, false);
        self::assertFalse($normal['complete']);
        self::assertSame('observed', $normal['sections']['uptime']['status']);
        self::assertSame('seconds', $normal['sections']['uptime']['unit']);
        self::assertSame('unsupported', $normal['sections']['listeners']['status']);
        self::assertSame('partial', $normal['sections']['memory']['status']);

        $truncated = SshOperatorProbes::parseSystem($raw, true);
        self::assertTrue($truncated['stdout_truncated']);
        self::assertFalse($truncated['complete']);
    }

    public function test_network_probe_requires_exact_quoted_destination_and_no_arbitrary_udp_success(): void
    {
        $script = SshOperatorProbes::networkScript('http', 'example.com', 8443, 'https', '/health?a=1&b=2', null, 5);
        self::assertStringContainsString("'https://example.com:8443/health?a=1&b=2'", $script);
        self::assertStringContainsString('--max-time 5', $script);
        self::assertStringNotContainsString('--location', $script);

        foreach ([
            fn () => SshOperatorProbes::networkScript('tcp', '-evil.test', 80, 'http', '/', null, 5),
            fn () => SshOperatorProbes::networkScript('udp_dns', '127.0.0.1', 53, 'http', '/', null, 5),
            fn () => SshOperatorProbes::networkScript('http', 'example.com', 80, 'http', '/ok'."\n".'bad', null, 5),
            fn () => SshOperatorProbes::systemScript(['service'], 'ssh.service; touch /tmp/unsafe'),
            fn () => SshOperatorProbes::journalScript(null, 'yesterday; rm -rf /', null, null, null, 10),
        ] as $invalid) {
            try {
                $invalid();
                self::fail('Invalid structured input unexpectedly accepted.');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }

        $sent = self::raw('completed', 0, "sent\n");
        $udp = SshOperatorProbes::parseNetwork('udp_dns', $sent);
        self::assertSame('failed', $udp['status'], 'Sending UDP alone is not a verified DNS reply.');

        $response = self::raw('completed', 0, ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n");
        $verified = SshOperatorProbes::parseNetwork('udp_dns', $response);
        self::assertSame('passed', $verified['status']);
        self::assertSame('NXDOMAIN', $verified['observed']['dns_response_status']);
        self::assertSame('unknown', SshOperatorProbes::parseNetwork('udp_dns', [
            ...$response, 'stdout_truncated' => true,
        ])['status']);
    }

    public function test_journal_cursor_and_timestamp_are_source_based_not_invented(): void
    {
        $raw = self::raw('completed', 0, '{"__CURSOR":"s=one","__REALTIME_TIMESTAMP":"1763770000123456","MESSAGE":"a","PRIORITY":"5","_SYSTEMD_UNIT":"demo.service"}'."\n"
            .'{"__CURSOR":"s=two","__REALTIME_TIMESTAMP":"1763770001123456","MESSAGE":"b"}'."\n"
            .'-- cursor: s=two'."\n");
        $journal = SshOperatorProbes::parseJournal($raw);
        self::assertSame('observed', $journal['status']);
        self::assertCount(2, $journal['entries']);
        self::assertSame('s=two', $journal['next_cursor']);
        self::assertStringEndsWith('123456Z', $journal['entries'][0]['timestamp_utc']);
        self::assertSame('demo.service', $journal['entries'][0]['source_unit']);
        self::assertTrue($journal['complete']);

        $unknown = SshOperatorProbes::parseJournal([...$raw, 'status' => 'outcome_unknown']);
        self::assertSame('unknown', $unknown['status']);
        self::assertFalse($unknown['complete']);
    }

    /** @return array<string,mixed> */
    private static function raw(string $status, int $exit, string $stdout): array
    {
        return [
            'status' => $status,
            'exit_code' => $exit,
            'stdout' => $stdout,
            'stderr' => '',
            'stdout_encoding' => 'utf-8',
            'stderr_encoding' => 'utf-8',
            'stdout_truncated' => false,
            'stderr_truncated' => false,
        ];
    }
}
