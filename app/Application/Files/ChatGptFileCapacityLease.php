<?php

namespace App\Application\Files;

use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * A caller-held short-lived reservation; release is idempotent.
 * PHP abort/worker death is reconciled by lease expiration at next admission.
 */
final class ChatGptFileCapacityLease
{
    private bool $released = false;

    public function __construct(private readonly string $id) {}

    public function release(): void
    {
        if ($this->released) {
            return;
        }
        try {
            DB::table('chatgpt_file_admission_leases')->where('id', $this->id)->delete();
            $this->released = true;
        } catch (Throwable) {
            // Do not falsely return capacity on DB outage. The bounded lease
            // will expire and be reclaimed by the next atomic admission.
        }
    }

    public function __destruct()
    {
        $this->release();
    }
}
