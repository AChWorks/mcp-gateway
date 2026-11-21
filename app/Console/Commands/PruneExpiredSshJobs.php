<?php

namespace App\Console\Commands;

use App\Application\Targets\SshJobCoordinator;
use Illuminate\Console\Command;

final class PruneExpiredSshJobs extends Command
{
    protected $signature = 'gateway:ssh-jobs-prune';

    protected $description = 'Prune completed, expired SSH Job spools with verified Target and user access.';

    public function handle(SshJobCoordinator $jobs): int
    {
        $report = $jobs->maintain();
        $this->components->info('SSH Job maintenance '.json_encode($report, JSON_THROW_ON_ERROR));

        return self::SUCCESS;
    }
}
