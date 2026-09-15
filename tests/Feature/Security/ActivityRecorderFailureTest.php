<?php

namespace Tests\Feature\Security;

use App\Infrastructure\Activity\ActivityRecorder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ActivityRecorderFailureTest extends TestCase
{
    use RefreshDatabase;

    public function test_activity_storage_failure_never_escapes_into_the_authoritative_operation(): void
    {
        Log::spy();
        Schema::drop('activity_retention_state');

        app(ActivityRecorder::class)->record(
            (string) Str::uuid(),
            'site-ability-execute',
            'success',
            'alpha',
        );

        self::assertSame(0, DB::table('activity_events')->count());
        Log::shouldHaveReceived('warning')->once();
    }
}
