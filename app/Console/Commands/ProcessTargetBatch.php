<?php

namespace App\Console\Commands;

use App\Application\Batch\TargetBatchWorker;
use Illuminate\Console\Command;
use Throwable;

final class ProcessTargetBatch extends Command
{
    protected $signature = 'gateway:batch-work {--once : Claim at most one Target} {--max-children=0 : Owner-adjustable per invocation work budget} {--max-seconds=0 : Owner-adjustable wall budget after any active child finishes}';

    protected $description = 'Process authorized, durable v3 Target Batch work; uncertain remote effects are never replayed.';

    public function handle(TargetBatchWorker $worker): int
    {
        $maxChildren = (int) $this->option('max-children');
        $maxSeconds = (int) $this->option('max-seconds');
        if ($maxChildren < 0 || $maxSeconds < 0) {
            $this->components->error('Work budgets must be nonnegative; zero uses the Owner-configured defaults.');

            return self::FAILURE;
        }
        $maxChildren = $this->option('once') ? 1 : ($maxChildren ?: max(1, (int) config('batch.worker_max_children', 16)));
        $maxSeconds = $maxSeconds ?: max(1, (int) config('batch.worker_max_seconds', 50));
        $start = hrtime(true);
        $done = 0;
        while ($done < $maxChildren && (hrtime(true) - $start) / 1_000_000_000 < $maxSeconds) {
            try {
                $result = $worker->workOnce();
            } catch (Throwable $exception) {
                // A post-claim exception may mean a remote effect has started.
                // Do not retry this invocation blindly; recovery keeps the
                // dispatch journal outcome unknown after its lease.
                $this->components->error('Batch worker halted: '.$exception::class.' '.$exception->getMessage());

                return self::FAILURE;
            }
            if ($result === null) {
                break;
            }
            $done++;
            $this->line(json_encode($result, JSON_THROW_ON_ERROR));
        }
        $this->components->info('Batch children handled: '.$done);

        return self::SUCCESS;
    }
}
