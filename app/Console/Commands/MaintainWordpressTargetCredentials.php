<?php

namespace App\Console\Commands;

use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
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
        foreach ($due as $id) {
            $target = Target::query()->find((string) $id);
            if (! $target instanceof Target) {
                continue;
            }

            try {
                $connections->routingContext($target, renewIfDue: true);
                $success++;
            } catch (WpAiBridgeTargetConnectionException $exception) {
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

        $this->info(sprintf('WordPress Target maintenance: renewed=%d failed=%d', $success, $failures));

        return $failures === 0 ? self::SUCCESS : self::FAILURE;
    }
}
