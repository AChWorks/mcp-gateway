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
