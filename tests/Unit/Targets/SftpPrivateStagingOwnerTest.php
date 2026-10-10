<?php

namespace Tests\Unit\Targets;

use App\Application\Targets\SshFileRuntime;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class SftpPrivateStagingOwnerTest extends TestCase
{
    public function test_sftp_v3_uid_must_be_available_and_equal_to_newly_created_inode(): void
    {
        $reflection = new ReflectionClass(SshFileRuntime::class);
        $runtime = $reflection->newInstanceWithoutConstructor();
        $matches = $reflection->getMethod('sameSftpOwner');

        self::assertTrue($matches->invoke($runtime, ['uid' => 1001, 'gid' => 123], ['uid' => 1001, 'gid' => 456], 3));
        self::assertFalse($matches->invoke($runtime, ['uid' => 1001], ['uid' => 0], 3));
        self::assertFalse($matches->invoke($runtime, ['uid' => 0], ['uid' => 1001], 3));
        self::assertFalse($matches->invoke($runtime, ['mode' => 0700], ['uid' => 1001], 3));
        self::assertFalse($matches->invoke($runtime, ['uid' => 1001], ['mode' => 0600], 3));
    }

    public function test_sftp_v4_owner_name_requires_nonempty_exact_match(): void
    {
        $reflection = new ReflectionClass(SshFileRuntime::class);
        $runtime = $reflection->newInstanceWithoutConstructor();
        $matches = $reflection->getMethod('sameSftpOwner');

        self::assertTrue($matches->invoke($runtime, ['owner' => 'alice@example.net'], ['owner' => 'alice@example.net'], 4));
        self::assertFalse($matches->invoke($runtime, ['owner' => 'bob@example.net'], ['owner' => 'alice@example.net'], 4));
        self::assertFalse($matches->invoke($runtime, ['owner' => ''], ['owner' => ''], 4));
        self::assertFalse($matches->invoke($runtime, ['uid' => 1001], ['uid' => 1001], 4));
    }
}
