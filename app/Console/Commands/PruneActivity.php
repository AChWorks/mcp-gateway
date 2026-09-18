<?php

namespace App\Console\Commands;

use App\Infrastructure\Activity\ActivityRetention;
use Illuminate\Console\Command;

final class PruneActivity extends Command
{
    protected $signature = 'activity:prune';

    protected $description = 'Apply the configured Activity retention policy.';

    public function handle(ActivityRetention $retention): int
    {
        $result = $retention->prune();

        $this->info(sprintf(
            'Activity retention pruned: expired=%d overflow=%d remaining=%d',
            $result['expired_deleted'],
            $result['overflow_deleted'],
            $result['remaining'],
        ));

        return self::SUCCESS;
    }
}
