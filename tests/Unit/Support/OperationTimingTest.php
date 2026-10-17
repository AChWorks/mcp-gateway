<?php

namespace Tests\Unit\Support;

use App\Support\OperationDiagnostics;
use App\Support\OperationTiming;
use Tests\TestCase;

final class OperationTimingTest extends TestCase
{
    public function test_only_bounded_fixed_numeric_fields_survive_safe_context(): void
    {
        $safe = OperationDiagnostics::safeContext(['timing' => [
            'total_ms' => 123,
            'mcp_initialize_ms' => 13,
            'outbound_calls' => 2,
            'curl_observed_calls' => 1,
            'raw_url' => 'https://private.example.test/?token=secret',
            'token' => 'Bearer private-token',
            'arbitrary_ms' => 999,
            'credential_ms' => OperationTiming::MAX_MS + 1,
            'mcp_close_ms' => -3,
            'dns_policy_ms' => 3.5,
            'target_lookup_ms' => '11',
            'mcp_execute_ms' => 12,
        ]]);

        self::assertSame(['timing' => [
            'total_ms' => 123,
            'mcp_initialize_ms' => 13,
            'mcp_execute_ms' => 12,
            'outbound_calls' => 2,
            'curl_observed_calls' => 1,
        ]], $safe);
        self::assertSame([], OperationDiagnostics::safeContext(['timing' => ['token' => 'secret']]));
    }

    public function test_raw_curl_stats_are_aggregated_without_urls_and_unmeasured_fields_are_absent(): void
    {
        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 0);
        $timing = OperationTiming::forWordpress();
        self::assertNotNull($timing);
        $timing->outboundCall();
        $timing->curlStats([
            'namelookup_time' => 0.001,
            'connect_time' => 0.004,
            'appconnect_time' => 0.014,
            'starttransfer_time' => 0.046,
            'url' => 'https://secret.example/credential',
            'bearer' => 'secret',
        ]);
        $timing->curlStats(['connect_time' => INF]);
        $timing->finish('not_a_stage', $timing->stamp());

        $details = $timing->details();
        self::assertSame(1, $details['timing']['outbound_calls']);
        self::assertSame(2, $details['timing']['curl_observed_calls']);
        self::assertSame(3, $details['timing']['tcp_connect_ms']);
        self::assertSame(10, $details['timing']['tls_handshake_ms']);
        self::assertSame(32, $details['timing']['first_byte_wait_ms']);
        self::assertArrayNotHasKey('not_a_stage', $details['timing']);
        self::assertStringNotContainsString('secret', json_encode($details, JSON_THROW_ON_ERROR));
    }

    public function test_disabled_and_slow_only_timing_behavior(): void
    {
        config()->set('bridge.timing.enabled', false);
        self::assertNull(OperationTiming::forWordpress());

        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 1800000);
        $timing = OperationTiming::forWordpress();
        self::assertNotNull($timing);
        self::assertSame([], $timing->details());
        self::assertArrayHasKey('timing', $timing->details(true));
    }
}
