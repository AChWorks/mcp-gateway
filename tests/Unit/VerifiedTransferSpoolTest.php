<?php

namespace Tests\Unit;

use App\Application\Files\VerifiedTransferSpool;
use App\Application\Targets\SshTargetConnectionException;
use PHPUnit\Framework\TestCase;

final class VerifiedTransferSpoolTest extends TestCase
{
    public function test_exact_binary_bytes_are_staged_without_allocating_the_full_configured_limit(): void
    {
        $bytes = "\x00\xff".random_bytes(1048576)."\r\n";
        $source = fopen('php://temp', 'w+b');
        fwrite($source, $bytes);
        rewind($source);

        $before = memory_get_peak_usage(true);
        $sink = VerifiedTransferSpool::capture(
            $source, strlen($bytes), hash('sha256', $bytes), 16 * 1048576,
            hrtime(true) + 10_000_000_000,
        );
        self::assertSame($bytes, stream_get_contents($sink));
        self::assertLessThanOrEqual(4 * 1048576, memory_get_peak_usage(true) - $before);
        fclose($sink);
        fclose($source);
    }

    public function test_empty_file_is_distinct_from_missing_data(): void
    {
        $source = fopen('php://temp', 'w+b');
        $sink = VerifiedTransferSpool::capture($source, 0, hash('sha256', ''), 1048576, hrtime(true) + 1000000000);
        self::assertSame('', stream_get_contents($sink));
        fclose($source);
        fclose($sink);
    }

    public function test_wrong_digest_is_rejected_before_remote_mutation(): void
    {
        $source = fopen('php://temp', 'w+b');
        fwrite($source, 'original');
        rewind($source);
        try {
            VerifiedTransferSpool::capture($source, 8, hash('sha256', 'tampered'), 1048576, hrtime(true) + 1000000000);
            self::fail('Mismatched SHA-256 must reject.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('input_changed', $exception->reason);
        } finally {
            fclose($source);
        }
    }

    public function test_extra_bytes_and_short_input_fail_closed(): void
    {
        foreach ([1, 9] as $declared) {
            $source = fopen('php://temp', 'w+b');
            fwrite($source, 'original');
            rewind($source);
            try {
                VerifiedTransferSpool::capture($source, $declared, hash('sha256', 'original'), 1048576, hrtime(true) + 1000000000);
                self::fail('Declared length mismatch must reject.');
            } catch (SshTargetConnectionException $exception) {
                self::assertSame('input_changed', $exception->reason);
            } finally {
                fclose($source);
            }
        }
    }

    public function test_over_budget_and_expired_deadline_reject_without_remote_data(): void
    {
        $source = fopen('php://temp', 'w+b');
        fwrite($source, 'original');
        rewind($source);
        try {
            VerifiedTransferSpool::capture($source, 8, hash('sha256', 'original'), 7, hrtime(true) + 1000000000);
            self::fail('Budget must reject.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('invalid_input', $exception->reason);
        }
        try {
            VerifiedTransferSpool::capture($source, 8, hash('sha256', 'original'), 10, hrtime(true) - 1);
            self::fail('Expired deadline must reject.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('transfer_timed_out', $exception->reason);
        }
        fclose($source);
    }
}
