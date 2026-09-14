<?php

namespace App\Console\Commands;

use App\Support\EnvironmentRequirements;
use Illuminate\Console\Command;

final class GatewayEnvironmentCheck extends Command
{
    protected $signature = 'gateway:check';

    protected $description = 'Validate the minimum MCP Gateway PHP, encryption, and database environment.';

    public function handle(EnvironmentRequirements $requirements): int
    {
        $checks = $requirements->checks(
            databaseDriver: (string) config('database.default'),
            applicationKey: config('app.key'),
            cipher: (string) config('app.cipher'),
        );

        foreach ($checks as $label => $passed) {
            $this->line(sprintf('%s %s', $passed ? '[OK]' : '[FAIL]', $label));
        }

        return in_array(false, $checks, true) ? self::FAILURE : self::SUCCESS;
    }
}
