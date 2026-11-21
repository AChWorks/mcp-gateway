<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('activity:prune')
    ->daily()
    ->withoutOverlapping();

Schedule::command('gateway:wordpress-credentials-maintain')
    ->everyMinute()
    ->withoutOverlapping();

// No dedicated Job worker; bounded cleanup reuses the installed scheduler.
Schedule::command('gateway:ssh-jobs-prune')
    ->hourly()
    ->withoutOverlapping();

// A single scheduler instance is conservative by default; operators may run
// several independent CLI workers to realize the configured concurrent mode.
Schedule::command('gateway:batch-work')
    ->everyMinute()
    ->withoutOverlapping(max(1, (int) config('batch.scheduler_lock_minutes', 10)));
