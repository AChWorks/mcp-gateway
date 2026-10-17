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
        self::assertSame(1, $details['timing']['curl_observed_calls']);
        self::assertSame(3, $details['timing']['tcp_connect_ms']);
        self::assertSame(10, $details['timing']['tls_handshake_ms']);
        self::assertSame(32, $details['timing']['first_byte_wait_ms']);
        self::assertArrayNotHasKey('not_a_stage', $details['timing']);
        self::assertStringNotContainsString('secret', json_encode($details, JSON_THROW_ON_ERROR));
    }

    public function test_zero_filled_and_nonempty_unusable_curl_stats_are_unmeasured(): void
    {
        $timing = $this->timing();
        $timing->curlStats([
            'num_connects' => 1,
            'namelookup_time' => 0.0,
            'connect_time' => 0.0,
            'appconnect_time' => 0.0,
            'starttransfer_time' => 0.0,
        ]);
        $timing->curlStats(['url' => 'https://private.example.test/?token=secret']);
        $timing->curlStats(['connect_time' => INF, 'starttransfer_time' => '0.021']);
        $timing->curlStats([]);

        $details = $timing->details()['timing'];
        self::assertSame(0, $details['curl_observed_calls']);
        foreach (['tcp_connect_ms', 'tls_handshake_ms', 'first_byte_wait_ms'] as $phase) {
            self::assertArrayNotHasKey($phase, $details);
        }
        self::assertStringNotContainsString('private.example.test', json_encode($details, JSON_THROW_ON_ERROR));
    }

    public function test_tcp_failure_before_connection_does_not_imply_any_completed_stage(): void
    {
        $timing = $this->timing();
        $timing->curlStats([
            'num_connects' => 0,
            'namelookup_time' => 0.001,
            'connect_time' => 0.0,
            'appconnect_time' => 0.0,
            'starttransfer_time' => 0.0,
        ]);

        $details = $timing->details()['timing'];
        self::assertSame(0, $details['curl_observed_calls']);
        self::assertArrayNotHasKey('tcp_connect_ms', $details);
        self::assertArrayNotHasKey('tls_handshake_ms', $details);
        self::assertArrayNotHasKey('first_byte_wait_ms', $details);
    }

    public function test_tcp_connect_succeeds_but_tls_fails_without_first_byte(): void
    {
        $timing = $this->timing();
        $timing->curlStats([
            'num_connects' => 1,
            'namelookup_time' => 0.001,
            'connect_time' => 0.021,
            'appconnect_time' => 0.0,
            'starttransfer_time' => 0.0,
        ]);

        $details = $timing->details()['timing'];
        self::assertSame(1, $details['curl_observed_calls']);
        self::assertSame(20, $details['tcp_connect_ms']);
        self::assertArrayNotHasKey('tls_handshake_ms', $details);
        self::assertArrayNotHasKey('first_byte_wait_ms', $details);
    }

    public function test_reused_connection_records_first_byte_without_repeating_tcp_or_tls(): void
    {
        $timing = $this->timing();
        $timing->curlStats([
            'num_connects' => 0,
            'namelookup_time' => 0.0,
            'connect_time' => 0.0,
            'appconnect_time' => 0.0,
            'starttransfer_time' => 0.005,
        ]);
        $timing->curlStats([
            'num_connects' => 0.0,
            'namelookup_time' => 0.001,
            'connect_time' => 0.003,
            'appconnect_time' => 0.011,
            'starttransfer_time' => 0.015,
        ]);

        $details = $timing->details()['timing'];
        self::assertSame(2, $details['curl_observed_calls']);
        self::assertArrayNotHasKey('tcp_connect_ms', $details);
        self::assertArrayNotHasKey('tls_handshake_ms', $details);
        self::assertSame(20, $details['first_byte_wait_ms']);
    }

    public function test_positive_milestones_preserve_actual_submillisecond_zero_deltas(): void
    {
        $timing = $this->timing();
        $timing->curlStats([
            'num_connects' => 1,
            'namelookup_time' => 0.0,
            'connect_time' => 0.0002,
            'appconnect_time' => 0.0004,
            'starttransfer_time' => 0.0006,
        ]);

        $details = $timing->details()['timing'];
        self::assertSame(1, $details['curl_observed_calls']);
        self::assertArrayHasKey('tcp_connect_ms', $details);
        self::assertArrayHasKey('tls_handshake_ms', $details);
        self::assertArrayHasKey('first_byte_wait_ms', $details);
        self::assertSame(0, $details['tcp_connect_ms']);
        self::assertSame(0, $details['tls_handshake_ms']);
        self::assertSame(0, $details['first_byte_wait_ms']);
    }

    public function test_partial_or_malformed_individual_milestones_do_not_fabricate_phases(): void
    {
        $timing = $this->timing();
        $timing->curlStats([
            'namelookup_time' => 'missing',
            'connect_time' => 0.011,
            'appconnect_time' => 0.018,
            'starttransfer_time' => 'unavailable',
        ]);
        $timing->curlStats([
            'namelookup_time' => null,
            'connect_time' => 0.0,
            'appconnect_time' => 0.0,
            'starttransfer_time' => 0.026,
        ]);

        $details = $timing->details()['timing'];
        self::assertSame(2, $details['curl_observed_calls']);
        self::assertArrayNotHasKey('tcp_connect_ms', $details);
        self::assertSame(7, $details['tls_handshake_ms']);
        self::assertSame(26, $details['first_byte_wait_ms']);
    }

    private function timing(): OperationTiming
    {
        config()->set('bridge.timing.enabled', true);
        config()->set('bridge.timing.minimum_ms', 0);
        $timing = OperationTiming::forWordpress();
        self::assertNotNull($timing);

        return $timing;
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
