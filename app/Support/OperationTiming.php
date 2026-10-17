<?php

namespace App\Support;

/**
 * Optional, request-local WordPress timing with a fixed numeric vocabulary.
 *
 * Does not retain bearer credentials, URLs, payloads, principal information,
 * exception text or request headers. Not shared across operations or requests.
 */
final class OperationTiming
{
    public const MAX_MS = 1_800_000;

    public const STAGES = [
        'target_lookup_ms',
        'authorization_ms',
        'credential_ms',
        'mcp_initialize_ms',
        'mcp_classification_ms',
        'mcp_catalog_ms',
        'mcp_execute_ms',
        'mcp_close_ms',
        'dns_policy_ms',
        'http_transport_ms',
        'tcp_connect_ms',
        'tls_handshake_ms',
        'first_byte_wait_ms',
    ];

    private readonly int $startNs;

    /** @var array<string,int> */
    private array $timings = [];

    private int $outboundCalls = 0;

    private int $curlObservedCalls = 0;

    private function __construct(private readonly int $minimumMs)
    {
        $this->startNs = hrtime(true);
    }

    public static function forWordpress(): ?self
    {
        if (config('bridge.timing.enabled', false) !== true) {
            return null;
        }

        return new self(max(0, min(self::MAX_MS, (int) config('bridge.timing.minimum_ms', 1500))));
    }

    public function stamp(): int
    {
        return hrtime(true);
    }

    public function finish(string $phase, int $startedNs): void
    {
        if (! in_array($phase, self::STAGES, true)) {
            return;
        }

        $elapsedNs = max(0, hrtime(true) - $startedNs);
        $this->add($phase, intdiv($elapsedNs, 1_000_000));
    }

    public function outboundCall(): void
    {
        $this->outboundCalls = min(128, $this->outboundCalls + 1);
    }

    /**
     * Observed cURL handler stats; absent stats are unmeasured, not zero.
     * All values are derived solely from known libcurl numeric timing fields.
     *
     * @param  array<string,mixed>  $stats
     */
    public function curlStats(array $stats): void
    {
        $lookup = $this->seconds($stats, 'namelookup_time');
        $connect = $this->seconds($stats, 'connect_time');
        $tls = $this->seconds($stats, 'appconnect_time');
        $firstByte = $this->seconds($stats, 'starttransfer_time');

        // libcurl reports zero for milestones not reached, as well as for
        // connections it reused. A positive raw value is the evidence that a
        // milestone occurred; the resulting sub-millisecond delta may round
        // legitimately to zero.
        $newConnection = ! in_array($stats['num_connects'] ?? null, [0, 0.0], true)
            && $connect !== null && $connect > 0;
        $tlsReached = $newConnection && $tls !== null && $tls > 0 && $tls >= $connect;
        $observed = false;

        if ($newConnection && $lookup !== null && $connect >= $lookup) {
            $this->add('tcp_connect_ms', (int) round(($connect - $lookup) * 1000));
            $observed = true;
        }
        if ($tlsReached) {
            $this->add('tls_handshake_ms', (int) round(($tls - $connect) * 1000));
            $observed = true;
        }

        // On a reused connection, a positive starttransfer_time still proves
        // first-byte arrival, even though TCP and TLS setup were not repeated.
        $ready = $tlsReached ? $tls : ($newConnection ? $connect : 0.0);
        if ($firstByte !== null && $firstByte > 0 && $firstByte >= $ready) {
            $this->add('first_byte_wait_ms', (int) round(($firstByte - $ready) * 1000));
            $observed = true;
        }

        if ($observed) {
            $this->curlObservedCalls = min(128, $this->curlObservedCalls + 1);
        }
    }

    /** @return array{timing:array<string,int>}|array{} */
    public function details(bool $failure = false): array
    {
        $total = min(self::MAX_MS, intdiv(max(0, hrtime(true) - $this->startNs), 1_000_000));
        if (! $failure && $total < $this->minimumMs) {
            return [];
        }

        return ['timing' => [
            'total_ms' => $total,
            ...$this->timings,
            'outbound_calls' => $this->outboundCalls,
            'curl_observed_calls' => $this->curlObservedCalls,
        ]];
    }

    private function add(string $key, int $ms): void
    {
        $this->timings[$key] = min(self::MAX_MS, ($this->timings[$key] ?? 0) + max(0, $ms));
    }

    /** @param array<string,mixed> $stats */
    private function seconds(array $stats, string $key): ?float
    {
        $value = $stats[$key] ?? null;
        if (! is_int($value) && ! is_float($value)) {
            return null;
        }

        $seconds = (float) $value;

        return is_finite($seconds) && $seconds >= 0 && $seconds <= 1800
            ? $seconds : null;
    }
}
