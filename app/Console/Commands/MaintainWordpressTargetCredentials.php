<?php

namespace App\Console\Commands;

use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;
use Throwable;

final class MaintainWordpressTargetCredentials extends Command
{
    protected $signature = 'gateway:wordpress-credentials-maintain {--limit=50}';

    protected $description = 'Renew due WordPress Target credentials before idle refresh-token expiry.';

    public function handle(WpAiBridgeTargetConnectionService $connections): int
    {
        $option = $this->option('limit');
        if (! is_string($option) || preg_match('/^[1-9][0-9]{0,2}$/D', $option) !== 1
            || (int) $option > 200) {
            $this->error('The limit must be an integer from 1 to 200.');

            return self::FAILURE;
        }

        // The due index lets us bound work without decrypting or probing
        // unrelated Targets. Intent-bearing credentials are never auto-replayed.
        $due = DB::table('wp_ai_bridge_credential_metadata as metadata')
            ->join('target_credentials as credentials', 'metadata.credential_id', '=', 'credentials.id')
            ->join('targets', 'credentials.target_record_id', '=', 'targets.id')
            ->where('targets.connector_type', 'wp_ai_bridge')
            ->where('targets.connection_state', TargetConnectionState::Connected->value)
            ->where('credentials.connector_type', 'wp_ai_bridge')
            ->where('credentials.purpose', 'wordpress_oauth')
            ->whereNotNull('metadata.refresh_due_at')
            ->where('metadata.refresh_due_at', '<=', now())
            ->whereNotExists(static function ($query): void {
                $query->selectRaw('1')
                    ->from('wp_ai_bridge_refresh_intents as intents')
                    ->whereColumn('intents.target_record_id', 'targets.id');
            })
            ->orderBy('metadata.refresh_due_at')
            ->limit((int) $option)
            ->pluck('targets.id');

        $success = 0;
        $failures = 0;
        $recovered = 0;
        /** @var list<array{record_id:string,target_id:string}> $recoveries */
        $recoveries = [];
        foreach ($due as $id) {
            // Drain an older recovery before its 45-second Gateway window
            // closes; waiting happens only once for the tail of the batch.
            $this->recoverPending($recoveries, $connections, $success, $failures, $recovered, false);
            $target = Target::query()->find((string) $id);
            if (! $target instanceof Target) {
                continue;
            }

            try {
                $connections->routingContext($target, renewIfDue: true);
                $success++;
            } catch (WpAiBridgeTargetConnectionException $exception) {
                if ($exception->reason === 'refresh_ambiguous') {
                    // A first rotating-token response can be lost. Bridge
                    // supports ONE same-client/Target old-token recovery for
                    // 60 seconds; the underlying service fences attempts and
                    // revocation. A minute-based cron cannot wait for a new
                    // tick and still reliably meet that deadline.
                    $recoveries[] = [
                        'record_id' => (string) $target->getKey(),
                        'target_id' => (string) $target->target_id,
                    ];

                    continue;
                }
                $failures++;
                Log::warning('WordPress Target credential maintenance declined.', [
                    'target_id' => $target->target_id,
                    'reason' => $exception->reason,
                ]);
            } catch (Throwable) {
                $failures++;
                Log::warning('WordPress Target credential maintenance encountered a local error.', [
                    'target_id' => $target->target_id,
                ]);
            }
        }

        $this->recoverPending($recoveries, $connections, $success, $failures, $recovered, true);
        $this->info(sprintf('WordPress Target maintenance: renewed=%d recovered=%d failed=%d',
            $success, $recovered, $failures));

        return $failures === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Finish only fresh ambiguous exchanges initiated in THIS maintenance
     * invocation. No workers, retrying stale/terminal refresh, or replay
     * past the single-use WordPress recovery window.
     *
     * @param  list<array{record_id:string,target_id:string}>  $pending
     */
    private function recoverPending(
        array &$pending,
        WpAiBridgeTargetConnectionService $connections,
        int &$success,
        int &$failures,
        int &$recovered,
        bool $waitForReady,
    ): void {
        $minimumAge = max(12, (int) config('bridge.http.request_timeout_seconds', 5) + 5);
        while ($pending !== []) {
            $current = $pending[0];
            $intent = DB::table('wp_ai_bridge_refresh_intents')
                ->where('target_record_id', $current['record_id'])
                ->first(['created_at', 'attempts']);
            $createdAt = $intent !== null ? strtotime((string) $intent->created_at) : false;
            $age = $createdAt === false ? 45 : time() - $createdAt;
            if ($intent === null || (int) $intent->attempts !== 1
                || $createdAt === false || $age < 0 || $age >= 45 || $minimumAge >= 45) {
                $failures++;
                Log::warning('WordPress Target automatic refresh recovery is unavailable.', [
                    'target_id' => $current['target_id'],
                    'reason' => 'refresh_recovery_window_unavailable',
                ]);
                array_shift($pending);

                continue;
            }
            if ($age < $minimumAge && ! $waitForReady) {
                // Let the remaining due Targets proceed while this exact
                // prior HTTP request settles, without a per-Target sleep.
                return;
            }

            if ($age < $minimumAge) {
                Sleep::sleep($minimumAge - $age);
            }
            $target = Target::query()->find($current['record_id']);
            try {
                if (! $target instanceof Target) {
                    throw new WpAiBridgeTargetConnectionException(
                        'target_not_found', 'The WordPress Target is no longer available.');
                }
                // Re-reads fresh DB intent/generation/permissions and enforces
                // only one recovery attempt; no untrusted URL or stored token
                // is ever exposed to this maintenance command.
                $connections->recoverAmbiguousRefresh($target);
                $success++;
                $recovered++;
            } catch (WpAiBridgeTargetConnectionException $exception) {
                $failures++;
                Log::warning('WordPress Target automatic refresh recovery declined.', [
                    'target_id' => $current['target_id'],
                    'reason' => $exception->reason,
                ]);
            } catch (Throwable) {
                $failures++;
                Log::warning('WordPress Target automatic refresh recovery failed locally.', [
                    'target_id' => $current['target_id'],
                ]);
            }
            array_shift($pending);
        }
    }
}
