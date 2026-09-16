<?php

namespace App\Infrastructure\Http;

use php_user_filter;

final class BoundedResponseBodyFilter extends php_user_filter
{
    public function filter($in, $out, &$consumed, bool $closing): int
    {
        if (! $this->params instanceof BoundedResponseBody) {
            return PSFS_ERR_FATAL;
        }

        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed += $bucket->datalen;

            if (! $this->params->acceptDecodedBytes($bucket->datalen)) {
                return PSFS_ERR_FATAL;
            }

            stream_bucket_append($out, $bucket);
        }

        return PSFS_PASS_ON;
    }
}
