<?php

namespace Tests\Unit\Targets;

use App\Application\Targets\SshCommandOutputCollector;
use phpseclib4\Net\SSH2;
use ReflectionClass;
use ReflectionProperty;
use RuntimeException;
use Tests\TestCase;

final class SshCommandOutputCollectorTest extends TestCase
{
    public function test_stdout_and_stderr_are_independent_bounded_streams_even_after_truncation(): void
    {
        // Exercise the installed phpseclib private buffer contract without
        // opening a socket or authorizing any remote command.
        $ssh = (new ReflectionClass(SSH2::class))->newInstanceWithoutConstructor();
        $log = new ReflectionProperty(SSH2::class, 'stdErrorLog');
        $log->setValue($ssh, '');
        $capture = new SshCommandOutputCollector($ssh, 16384, 8192);
        $capture->observe($ssh, str_repeat('o', 16384));
        $capture->observe($ssh, str_repeat('x', 32768));
        $log->setValue($ssh, str_repeat('e', 8192));
        $capture->observe($ssh, str_repeat('e', 8192));
        self::assertSame('', $log->getValue($ssh), 'Vendor stderr log must be cleared after every packet.');
        $log->setValue($ssh, str_repeat('z', 25000));
        $capture->observe($ssh, str_repeat('z', 25000));
        $capture->observe($ssh, "\x00\xff");

        $result = $capture->result();
        self::assertSame(str_repeat('o', 16384), $result['stdout']);
        self::assertSame(str_repeat('e', 8192), $result['stderr']);
        self::assertSame(49154, $result['stdout_total_bytes']);
        self::assertSame(33192, $result['stderr_total_bytes']);
        self::assertSame(16384, $result['stdout_bytes']);
        self::assertSame(8192, $result['stderr_bytes']);
        self::assertTrue($result['stdout_truncated']);
        self::assertTrue($result['stderr_truncated']);
        self::assertSame('', $log->getValue($ssh));
    }

    public function test_ambiguous_stream_callback_fails_closed_instead_of_silent_mislabeling(): void
    {
        $ssh = (new ReflectionClass(SSH2::class))->newInstanceWithoutConstructor();
        $log = new ReflectionProperty(SSH2::class, 'stdErrorLog');
        $log->setValue($ssh, 'stderr-part');
        $capture = new SshCommandOutputCollector($ssh, 16384, 8192);
        $this->expectException(RuntimeException::class);
        $capture->observe($ssh, 'different-part');
    }

    public function test_synthetic_multi_megabyte_stdout_stderr_do_not_accumulate(): void
    {
        $ssh = (new ReflectionClass(SSH2::class))->newInstanceWithoutConstructor();
        $log = new ReflectionProperty(SSH2::class, 'stdErrorLog');
        $log->setValue($ssh, '');
        $capture = new SshCommandOutputCollector($ssh, 16384, 8192);
        $chunk = str_repeat('A', 8192);
        for ($i = 0; $i < 512; $i++) {
            $capture->observe($ssh, $chunk);
            $log->setValue($ssh, $chunk);
            $capture->observe($ssh, $chunk);
        }
        $result = $capture->result();
        self::assertSame(4194304, $result['stdout_total_bytes']);
        self::assertSame(4194304, $result['stderr_total_bytes']);
        self::assertSame(16384, strlen($result['stdout']));
        self::assertSame(8192, strlen($result['stderr']));
        self::assertSame('', $log->getValue($ssh));
    }
}
