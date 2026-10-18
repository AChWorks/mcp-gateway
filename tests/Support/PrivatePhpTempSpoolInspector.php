<?php

namespace Tests\Support;

use RuntimeException;

/**
 * Linux-only, read-only FD fixture: observe real php://temp disk spills while
 * their owning streams are open. This does not mock the admission arithmetic.
 */
final class PrivatePhpTempSpoolInspector
{
    /** @return array<string, int> PHP temporary pathname => actual open-file length */
    public static function openDiskSpools(): array
    {
        $names = @scandir('/proc/self/fd');
        if (! is_array($names)) {
            throw new RuntimeException('The file-spool acceptance fixture requires Linux /proc/self/fd.');
        }

        $spools = [];
        foreach ($names as $name) {
            if (! ctype_digit($name)) {
                continue;
            }
            $fd = '/proc/self/fd/'.$name;
            $target = @readlink($fd);
            if (! is_string($target) || preg_match('~(?:^|/)php[a-zA-Z0-9]+(?: \(deleted\))?$~D', $target) !== 1) {
                continue;
            }

            $stat = @stat($fd);
            if (! is_array($stat)) {
                throw new RuntimeException('A PHP disk-backed temporary file disappeared during the fixture.');
            }
            $spools[$target] = (int) $stat['size'];
        }

        ksort($spools);

        return $spools;
    }

    /**
     * @param  array<string,int>  $baseline
     * @return array<string,int>
     */
    public static function additionalSince(array $baseline): array
    {
        return array_diff_key(self::openDiskSpools(), $baseline);
    }
}
