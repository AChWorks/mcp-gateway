<?php

namespace App\Application\Targets;

use App\Application\Operations\OperationalSettings;
use App\Domain\Targets\Target;
use App\Models\User;

/**
 * Localized, explicit patching through the existing bounded SFTP reader/writer.
 * The SHA256 precondition detects observed drift; it is not remote atomic CAS.
 */
final readonly class SshFilePatchService
{
    public function __construct(
        private SshFileRuntime $files,
        private OperationalSettings $settings,
    ) {}

    /** @return array<string,mixed> */
    public function patch(
        User $user, Target $target, string $path, string $find, string $replace,
        bool $apply = false, ?string $expectedSha256 = null,
    ): array {
        if ($find === '' || strlen($path) > 1024 || strlen($find) > $this->maxFileBytes()
            || strlen($replace) > $this->maxFileBytes()
            || ! mb_check_encoding($find, 'UTF-8') || ! mb_check_encoding($replace, 'UTF-8')
            || str_contains($find, "\0") || str_contains($replace, "\0")
            || ($expectedSha256 !== null && preg_match('/^[a-f0-9]{64}$/D', $expectedSha256) !== 1)
            || ($apply && $expectedSha256 === null)) {
            throw new SshTargetConnectionException('invalid_input');
        }

        $snapshot = $this->snapshot($user, $target, $path);
        $before = $snapshot['content'];
        if (! mb_check_encoding($before, 'UTF-8') || str_contains($before, "\0")) {
            throw new SshTargetConnectionException('unsupported_binary_file');
        }
        $beforeSha = hash('sha256', $before);
        if ($expectedSha256 !== null && ! hash_equals($expectedSha256, $beforeSha)) {
            throw new SshTargetConnectionException('source_changed');
        }
        if (substr_count($before, $find) !== 1) {
            throw new SshTargetConnectionException('patch_match_not_unique');
        }

        $offset = strpos($before, $find);
        $after = substr_replace($before, $replace, $offset, strlen($find));
        if (strlen($after) > $this->maxFileBytes()) {
            throw new SshTargetConnectionException('inline_patch_window_exceeded');
        }
        $afterSha = hash('sha256', $after);
        $plan = [
            'path' => $path,
            'source' => 'sftp',
            'baseline_sha256' => $beforeSha,
            'proposed_sha256' => $afterSha,
            'source_size' => $snapshot['size'],
            'source_mtime' => $snapshot['mtime'],
            'source_mode' => $snapshot['mode'],
            'source_uid' => $snapshot['uid'],
            'source_gid' => $snapshot['gid'],
            'owner_preservation' => 'must_match_or_reject',
            'source_consistency' => 'sha256_preflight_plus_best_effort_size_mtime_not_atomic_cas',
            'diff' => $this->diff($path, $before, $after),
            'change_required' => ! hash_equals($beforeSha, $afterSha),
        ];
        if (! $apply || ! $plan['change_required']) {
            return [
                'status' => 'preview',
                'observed_at' => now('UTC')->toIso8601String(),
                'complete' => true,
                'remote_mutation' => false,
                ...$plan,
            ];
        }

        $write = $this->files->write(
            $user, $target, $path, base64_encode($after), true,
            $snapshot['size'], $snapshot['mtime'],
            preserveOriginalOwner: true,
        );
        if ($write['status'] !== 'completed') {
            // Even if staging cleanup succeeded, uncertain publication must
            // never be retried or misreported as a confirmed rollback.
            return [
                'status' => 'outcome_unknown',
                'complete' => false,
                'possible_remote_effect' => true,
                'next_step' => 'Inspect the exact remote file hash and service state; do not replay automatically.',
                '__diagnostic_context' => $write['__diagnostic_context'] ?? [],
                ...$plan,
            ];
        }

        // Independent new SFTP session; verify AFTER publication, not just
        // the writer's staging readback. No automatic replay on lost response.
        try {
            $readback = $this->snapshot($user, $target, $path);
            $verified = hash_equals($afterSha, hash('sha256', $readback['content']))
                && $readback['mode'] === $snapshot['mode']
                && $readback['uid'] === $snapshot['uid']
                && $readback['gid'] === $snapshot['gid'];
        } catch (\Throwable) {
            $verified = false;
        }
        if (! $verified) {
            return [
                'status' => 'outcome_unknown',
                'complete' => false,
                'possible_remote_effect' => true,
                'next_step' => 'The write was reported complete but independent readback/identity verification failed; inspect before any recovery.',
                ...$plan,
            ];
        }

        return [
            'status' => 'completed',
            'complete' => true,
            'file_modified' => true,
            'syntax_validated' => false,
            'service_reloaded' => false,
            'service_healthy' => null,
            'published_sha256' => $afterSha,
            'readback_verified' => true,
            'owner_and_mode_verified' => true,
            'observed_at' => now('UTC')->toIso8601String(),
            ...$plan,
        ];
    }

    /** @return array{content:string,size:int,mtime:int,mode:string,uid:mixed,gid:mixed} */
    public function snapshot(User $user, Target $target, string $path): array
    {
        return $this->files->readForPatch($user, $target, $path);
    }

    private function maxFileBytes(): int
    {
        return $this->settings->sshFileLimits()['write_bytes'];
    }

    /** @return array{unified:string,truncated:bool} */
    private function diff(string $path, string $before, string $after): array
    {
        if ($before === $after) {
            return ['unified' => '', 'truncated' => false];
        }

        // A localized replacement can insert/remove newlines. Identify its
        // actual changed *lines*, rather than estimating hunk counts from
        // replacement byte lengths (which is wrong at EOF and line breaks).
        $old = self::lines($before);
        $new = self::lines($after);
        $oldTotal = count($old);
        $newTotal = count($new);
        $prefix = 0;
        while ($prefix < min($oldTotal, $newTotal) && $old[$prefix] === $new[$prefix]) {
            $prefix++;
        }
        $suffix = 0;
        while ($suffix < $oldTotal - $prefix && $suffix < $newTotal - $prefix
            && $old[$oldTotal - $suffix - 1] === $new[$newTotal - $suffix - 1]) {
            $suffix++;
        }
        $leading = min(3, $prefix);
        $trailing = min(3, $suffix);
        $oldChanged = $oldTotal - $prefix - $suffix;
        $newChanged = $newTotal - $prefix - $suffix;
        $firstIndex = $prefix - $leading;
        $oldCount = $leading + $oldChanged + $trailing;
        $newCount = $leading + $newChanged + $trailing;

        // In a zero-length side of a unified hunk the start points to
        // the line BEFORE insertion/deletion (0 when the file was empty).
        $oldStart = $firstIndex + ($oldCount === 0 ? 0 : 1);
        $newStart = $firstIndex + ($newCount === 0 ? 0 : 1);
        $diff = "--- a/$path\n+++ b/$path\n"
            ."@@ -$oldStart,$oldCount +$newStart,$newCount @@\n";

        foreach (array_slice($old, $firstIndex, $leading) as $line) {
            $diff .= self::diffLine(' ', $line);
        }
        foreach (array_slice($old, $prefix, $oldChanged) as $line) {
            $diff .= self::diffLine('-', $line);
        }
        foreach (array_slice($new, $prefix, $newChanged) as $line) {
            $diff .= self::diffLine('+', $line);
        }
        foreach (array_slice($old, $oldTotal - $suffix, $trailing) as $line) {
            $diff .= self::diffLine(' ', $line);
        }

        $limit = $this->settings->sshCommandOutputLimits()['stdout_bytes'];
        $truncated = strlen($diff) > $limit;

        return [
            // Byte bounded but always valid UTF-8, even at the middle of
            // Persian / multibyte content. The separate flag means a cut
            // preview is never represented as a complete applicable patch.
            'unified' => $truncated ? mb_strcut($diff, 0, $limit, 'UTF-8') : $diff,
            'truncated' => $truncated,
        ];
    }

    /** @return list<string> Lines retain their original LF and final-newline state. */
    private static function lines(string $text): array
    {
        if ($text === '') {
            return [];
        }
        $parts = explode("\n", $text);
        $last = count($parts) - 1;
        $lines = [];
        foreach ($parts as $index => $part) {
            if ($index < $last) {
                $lines[] = $part."\n";
            } elseif ($part !== '') {
                $lines[] = $part;
            }
        }

        return $lines;
    }

    private static function diffLine(string $prefix, string $line): string
    {
        return $prefix.$line.(str_ends_with($line, "\n") ? '' : "\n\\ No newline at end of file\n");
    }
}
