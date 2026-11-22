<?php

namespace Tests\Unit\Targets;

use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshFilePatchService;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionMethod;
use Symfony\Component\Process\Process;
use Tests\TestCase;

final class SshFilePatchDiffTest extends TestCase
{
    /** @return array<string,array{string,string}> */
    public static function changes(): array
    {
        return [
            'single complete line' => ["foo\n", "bar\n"],
            'single unterminated line' => ['foo', 'bar'],
            'terminal LF added' => ['foo', "foo\n"],
            'terminal LF removed' => ["foo\n", 'foo'],
            'multiline replacement' => ["head\none\ntwo\ntail\n", "head\nUNO\nDOS\ntail\n"],
            'whole-line insertion' => ["head\ntail\n", "head\ninserted\ntail\n"],
            'joined lines' => ["head\nold\ntail\n", "headold\ntail\n"],
            'new lines at EOF' => ["head\n", "head\ntail\n"],
            'Persian UTF-8' => ["عنوان=قدیم\n", "عنوان=جدید\n"],
            'CRLF lines' => ["head\r\nold\r\ntail\r\n", "head\r\nnew\r\ntail\r\n"],
            'long unchanged prefix and suffix' => [
                "a\nb\nc\nd\nold\n1\n2\n3\n4\n5\n", "a\nb\nc\nd\nnew\n1\n2\n3\n4\n5\n",
            ],
            'insertion into unterminated final line' => ["head\ntail", "head\ntail suffix"],
        ];
    }

    #[DataProvider('changes')]
    public function test_localized_diff_has_exact_unified_line_counts_and_applies_to_original(
        string $before, string $after,
    ): void {
        $diff = $this->diff($before, $after);
        self::assertFalse($diff['truncated']);
        self::assertTrue(mb_check_encoding($diff['unified'], 'UTF-8'));
        self::assertMatchesRegularExpression('/^--- a\/fixture\.conf\n\+\+\+ b\/fixture\.conf\n@@ -\d+,\d+ \+\d+,\d+ @@\n/', $diff['unified']);
        if ($before === "foo\n" && $after === "bar\n") {
            self::assertStringContainsString("@@ -1,1 +1,1 @@\n-foo\n+bar\n", $diff['unified']);
            self::assertStringNotContainsString("\n-\n", $diff['unified']);
        }
        if (str_ends_with($before, "\n") !== str_ends_with($after, "\n")) {
            self::assertStringContainsString('\\ No newline at end of file', $diff['unified']);
        }

        $directory = sys_get_temp_dir().'/gateway-ssh-diff-'.bin2hex(random_bytes(8));
        self::assertTrue(mkdir($directory, 0700));
        $file = $directory.'/fixture.conf';
        try {
            self::assertSame(strlen($before), file_put_contents($file, $before));
            $patch = new Process(['patch', '--batch', '--no-backup-if-mismatch', '-p1'], $directory);
            $patch->setInput($diff['unified']);
            $patch->run();
            self::assertTrue($patch->isSuccessful(), $patch->getErrorOutput()."\n".$patch->getOutput());
            self::assertSame($after, file_get_contents($file));
        } finally {
            @unlink($file);
            @rmdir($directory);
        }
    }

    public function test_truncation_is_byte_bounded_utf8_safe_and_explicitly_incomplete(): void
    {
        $before = str_repeat('ک', 13000)."\n";
        $after = str_repeat('گ', 13000)."\n";
        $diff = $this->diff($before, $after);
        $limit = app(OperationalSettings::class)->sshCommandOutputLimits()['stdout_bytes'];

        self::assertTrue($diff['truncated']);
        self::assertLessThanOrEqual($limit, strlen($diff['unified']));
        self::assertTrue(mb_check_encoding($diff['unified'], 'UTF-8'));
        self::assertNotFalse(json_encode($diff, JSON_THROW_ON_ERROR));
    }

    public function test_unchanged_content_does_not_claim_a_hunk(): void
    {
        self::assertSame(
            ['unified' => '', 'truncated' => false],
            $this->diff("same\n", "same\n"),
        );
    }

    /** @return array{unified:string,truncated:bool} */
    private function diff(string $before, string $after): array
    {
        $method = new ReflectionMethod(SshFilePatchService::class, 'diff');

        return $method->invoke(app(SshFilePatchService::class), 'fixture.conf', $before, $after);
    }
}
