<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('activity:prune')
    ->daily()
    ->withoutOverlapping();

Schedule::command('gateway:wordpress-credentials-maintain')
    ->everyMinute()
    ->withoutOverlapping();
