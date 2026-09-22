<?php

namespace Tests\Feature\Security;

use App\Infrastructure\Activity\ActivityRecorder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-activity')]
final class ActivityWriteDatabaseTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('MariaDB or MySQL is required for Activity hot-path database validation.');
        }
    }

    public function test_activity_write_is_a_single_insert_without_retention_queries(): void
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        app(ActivityRecorder::class)->record(
            (string) Str::uuid(),
            'site-ability-execute',
            'success',
            'site-00001',
        );

        $queries = DB::getQueryLog();
        DB::disableQueryLog();
        $activityQueries = array_values(array_filter(
            $queries,
            static fn (array $query): bool => str_contains(strtolower((string) $query['query']), 'activity_'),
        ));

        self::assertCount(1, $activityQueries);
        self::assertStringContainsString('insert', strtolower((string) $activityQueries[0]['query']));
        self::assertStringContainsString('activity_events', strtolower((string) $activityQueries[0]['query']));
        self::assertSame(1, DB::table('activity_events')->count());
    }
}
