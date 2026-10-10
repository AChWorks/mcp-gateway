<?php

namespace Tests\Feature\Security;

use App\Application\Mcp\TargetMcpToolHandlers;
use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ActivityRecorderFailureTest extends TestCase
{
    use RefreshDatabase;

    public function test_activity_write_hot_path_is_one_insert_and_does_not_depend_on_retention_lock_state(): void
    {
        // The query trace proves no retention-state lookup is attempted.
        // Dropping a MySQL table here implicitly commits Laravel's outer
        // test transaction and can leak unrelated Activity fixtures.
        $before = DB::table('activity_events')->count();
        DB::flushQueryLog();
        DB::enableQueryLog();

        app(ActivityRecorder::class)->record(
            (string) Str::uuid(),
            'wordpress-ability-execute',
            'success',
        );

        $queries = DB::getQueryLog();
        DB::disableQueryLog();
        $activityQueries = array_values(array_filter(
            $queries,
            static fn (array $query): bool => str_contains(strtolower((string) $query['query']), 'activity_'),
        ));

        $inserts = array_values(array_filter($activityQueries,
            static fn (array $query): bool => str_starts_with(strtolower(trim((string) $query['query'])), 'insert into')
                && str_contains(strtolower((string) $query['query']), 'activity_events')));
        self::assertCount(1, $inserts);
        self::assertCount(0, array_filter($activityQueries,
            static fn (array $query): bool => str_contains(strtolower((string) $query['query']), 'activity_retention_state')));

        self::assertSame($before + 1, DB::table('activity_events')->count());
    }

    public function test_activity_storage_failure_never_escapes_into_the_authoritative_operation(): void
    {
        Log::spy();
        Schema::drop('activity_events');

        app(ActivityRecorder::class)->record(
            (string) Str::uuid(),
            'wordpress-ability-execute',
            'success',
        );

        Log::shouldHaveReceived('warning')->once();
    }

    public function test_secret_shaped_unknown_site_id_is_not_retained_or_returned(): void
    {
        $secretSiteId = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature';
        $principal = $this->owner();
        $results = [
            app(TargetMcpToolHandlers::class)->targetContext($principal, $secretSiteId),
            app(WordpressTargetMcpToolHandlers::class)->read($principal, $secretSiteId),
            app(WordpressTargetMcpToolHandlers::class)->execute($principal, $secretSiteId, 'demo/read', []),
        ];

        foreach ($results as $result) {
            self::assertFalse($result['ok']);
            self::assertSame('target_not_found', $result['error']['code']);
            self::assertStringNotContainsString($secretSiteId, json_encode($result, JSON_THROW_ON_ERROR));
        }

        $events = DB::table('activity_events')->orderBy('created_at')->orderBy('id')->get();
        self::assertCount(3, $events);
        self::assertSame(
            ['target-context', 'wordpress-abilities-read', 'wordpress-ability-execute'],
            $events->pluck('operation')->all(),
        );

        foreach ($events as $event) {
            self::assertNull($event->target_id);
            self::assertSame('failure', $event->outcome);
            self::assertSame('target_not_found', $event->error_code);
        }

        self::assertStringNotContainsString($secretSiteId, json_encode($events->all(), JSON_THROW_ON_ERROR));
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Activity Test Owner',
            'email' => 'activity-test-owner-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
        ]);
    }

    public function test_secret_shaped_unknown_site_id_is_not_written_to_fallback_log_context(): void
    {
        $secretSiteId = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature';
        Log::spy();
        Schema::drop('activity_events');

        $result = app(WordpressTargetMcpToolHandlers::class)
            ->execute($this->owner(), $secretSiteId, 'demo/read', []);

        self::assertFalse($result['ok']);
        self::assertSame('target_not_found', $result['error']['code']);
        self::assertStringNotContainsString($secretSiteId, json_encode($result, JSON_THROW_ON_ERROR));

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(function (string $message, array $context) use ($secretSiteId): bool {
                return $message === 'Gateway activity persistence failed.'
                    && array_key_exists('target_id', $context)
                    && $context['target_id'] === null
                    && ! str_contains(json_encode($context, JSON_THROW_ON_ERROR), $secretSiteId);
            });
    }
}
