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

    public function test_patch_publication_requires_all_original_mode_bits_but_plain_write_keeps_ordinary_contract(): void
    {
        $check = (new ReflectionClass(SshFileRuntime::class))->getMethod('publicationModeMatches');

        foreach ([0644, 0755, 04755, 02755, 01755, 06755] as $mode) {
            self::assertTrue($check->invoke(null, ['mode' => 0100000 | $mode], $mode, true));
            self::assertFalse($check->invoke(null, ['mode' => 0100000 | ($mode ^ 0001)], $mode, true));
        }
        self::assertFalse($check->invoke(null, ['mode' => 0100755], 04755, true));
        self::assertFalse($check->invoke(null, ['mode' => 0100755], 02755, true));
        self::assertFalse($check->invoke(null, ['mode' => 0100755], 01755, true));
        self::assertFalse($check->invoke(null, ['mode' => '04755'], 04755, true));
        // No unrelated behavior change for generic ssh-file-write:
        self::assertTrue($check->invoke(null, ['mode' => 0104755], 0755, false));
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
