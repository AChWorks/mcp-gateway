<?php

namespace Tests\Feature\Security;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ActivityRetentionTest extends TestCase
{
    use RefreshDatabase;

    public function test_operator_prune_enforces_age_and_row_cap_without_recording_new_activity(): void
    {
        config()->set('activity.retention_days', 30);
        config()->set('activity.max_rows', 3);

        $this->insertActivity('expired-1', now()->subDays(31));
        $this->insertActivity('expired-2', now()->subDays(45));

        for ($index = 1; $index <= 5; $index++) {
            $this->insertActivity('recent-'.$index, now()->subMinutes(5 - $index));
        }

        $this->artisan('activity:prune')
            ->expectsOutput('Activity retention pruned: expired=2 overflow=2 remaining=3')
            ->assertSuccessful();

        self::assertSame(3, DB::table('activity_events')->count());
        self::assertSame(
            ['recent-3', 'recent-4', 'recent-5'],
            DB::table('activity_events')->orderBy('created_at')->pluck('site_id')->all(),
        );
    }

    public function test_operator_prune_is_idempotent_when_policy_is_already_satisfied(): void
    {
        config()->set('activity.retention_days', 30);
        config()->set('activity.max_rows', 3);

        $this->insertActivity('recent', now());

        $this->artisan('activity:prune')
            ->expectsOutput('Activity retention pruned: expired=0 overflow=0 remaining=1')
            ->assertSuccessful();

        self::assertDatabaseHas('activity_events', ['site_id' => 'recent']);
    }

    private function insertActivity(string $siteId, mixed $createdAt): void
    {
        DB::table('activity_events')->insert([
            'id' => (string) Str::ulid(),
            'correlation_id' => (string) Str::uuid(),
            'actor_type' => 'system',
            'actor_id' => null,
            'client_id_hash' => null,
            'site_id' => $siteId,
            'operation' => 'retention-test',
            'outcome' => 'success',
            'error_code' => null,
            'created_at' => $createdAt,
        ]);
    }
}
