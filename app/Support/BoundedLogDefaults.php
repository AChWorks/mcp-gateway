<?php

namespace App\Support;

final class BoundedLogDefaults
{
    /** @return array{0:mixed,1:string} */
    public static function normalize(mixed $channel, string $stackChannels): array
    {
        if ($channel === 'stack' && $stackChannels === 'single') {
            return ['daily', 'daily'];
        }

        return [$channel, $stackChannels];
    }
}
