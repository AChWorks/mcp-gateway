<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('activity:prune')
    ->daily()
    ->withoutOverlapping();
