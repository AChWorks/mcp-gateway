<?php

namespace App\Application\Files;

use App\Infrastructure\Http\OutboundRequestException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * Transactional admission for the total in-flight temporary spool footprint
 * across all PHP workers and all Gateway nodes sharing the authoritative DB.
 * Nothing is fetched until a bounded slot AND its worst-case bytes are owned.
 */
final readonly class ChatGptFileCapacity
{
    private const GRACE_SECONDS = 30;

    /** @return array{max_active:int,max_reserved_bytes:int,wordpress_max_active:int,ssh_max_active:int} */
    public function limits(): array
    {
        return [
            'max_active' => min(16, max(1, (int) config('bridge.file_input.capacity.max_active', 4))),
            'max_reserved_bytes' => min(536870912, max(1048576,
                (int) config('bridge.file_input.capacity.max_reserved_bytes', 134217728))),
            'wordpress_max_active' => min(16, max(1,
                (int) config('bridge.file_input.capacity.wordpress_max_active', 2))),
            'ssh_max_active' => min(16, max(1,
                (int) config('bridge.file_input.capacity.ssh_max_active', 2))),
        ];
    }

    /**
     * Allocate by SOURCE size budget, not declared Content-Length or measured
     * bytes. WP has one local spill-to-disk stream. SSH additionally verifies
     * into a second PHP private stream before publishing remotely.
     */
    public function reserve(string $mode, int $maxBytes, int $maxSeconds): ChatGptFileCapacityLease
    {
        if (! in_array($mode, ['wordpress', 'ssh'], true)
            || $maxBytes < 1 || $maxBytes > 67108864
            || $maxSeconds < 1 || $maxSeconds > 120) {
            throw new OutboundRequestException('file_capacity_unavailable', 'File admission parameters are invalid.');
        }
        $reserveBytes = $maxBytes * ($mode === 'ssh' ? 2 : 1);
        $limits = $this->limits();
        if ($reserveBytes > $limits['max_reserved_bytes']) {
            throw new OutboundRequestException('file_capacity_exceeded', 'Temporary file admission capacity is exhausted.');
        }

        try {
            $id = DB::transaction(static function () use ($mode, $reserveBytes, $maxSeconds, $limits): string {
                if (DB::table('chatgpt_file_admission_guard')->where('id', 1)->lockForUpdate()->first() === null) {
                    throw new OutboundRequestException('file_capacity_unavailable', 'Temporary file admission is unavailable.');
                }

                // Crashed PHP workers close their php://temp spools automatically.
                // Expire only after the whole-transfer timeout PLUS a conservative
                // grace period, never during the contractual normal operation.
                DB::table('chatgpt_file_admission_leases')->where('expires_at', '<=', now())->delete();

                $active = DB::table('chatgpt_file_admission_leases')
                    ->get(['mode', 'reserved_bytes']);
                $used = 0;
                $modeActive = 0;
                foreach ($active as $row) {
                    $used += (int) $row->reserved_bytes;
                    if ($row->mode === $mode) {
                        $modeActive++;
                    }
                }
                $modeLimit = $mode === 'ssh' ? $limits['ssh_max_active'] : $limits['wordpress_max_active'];
                if ($active->count() >= $limits['max_active']
                    || $modeActive >= $modeLimit
                    || $used + $reserveBytes > $limits['max_reserved_bytes']) {
                    throw new OutboundRequestException('file_capacity_exceeded', 'Temporary file admission capacity is exhausted.');
                }

                $id = (string) Str::uuid();
                DB::table('chatgpt_file_admission_leases')->insert([
                    'id' => $id,
                    'mode' => $mode,
                    'reserved_bytes' => $reserveBytes,
                    'expires_at' => now()->addSeconds($maxSeconds + self::GRACE_SECONDS),
                    'created_at' => now(),
                ]);

                return $id;
            }, 3);
        } catch (OutboundRequestException $exception) {
            throw $exception;
        } catch (Throwable) {
            // Fail closed on migration absence, database outage or lock error.
            throw new OutboundRequestException('file_capacity_unavailable', 'Temporary file admission is unavailable.');
        }

        return new ChatGptFileCapacityLease($id);
    }
}
