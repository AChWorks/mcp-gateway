<?php

namespace Tests\Feature\Security;

use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

final class SelfCreatedTargetAttributionMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_existing_target_attribution_uses_first_owner_and_does_not_materialize_acl_grants(): void
    {
        $first = $this->user('owner');
        $second = $this->user('owner');
        $other = $this->user('administrator');
        foreach (['historic-ssh', 'historic-wp'] as $id) {
            Target::query()->create([
                'target_id' => $id,
                'display_name' => $id,
                'connector_type' => $id === 'historic-ssh' ? 'ssh_direct' : 'wp_ai_bridge',
            ]);
        }
        $migration = require database_path('migrations/2026_11_21_030000_attribute_existing_targets_to_owner.php');
        $migration->down();
        self::assertFalse(Schema::hasColumn('targets', 'created_by_user_id'));
        $migration->up();

        self::assertSame([$first->id, $first->id], DB::table('targets')
            ->orderBy('target_id')->pluck('created_by_user_id')->all());
        self::assertSame(0, DB::table('user_target_access')->count());
        self::assertFalse((bool) DB::table('users')->where('id', $first->id)
            ->value('self_created_target_access'));
        self::assertFalse((bool) DB::table('users')->where('id', $second->id)
            ->value('self_created_target_access'));
        self::assertFalse((bool) DB::table('users')->where('id', $other->id)
            ->value('self_created_target_access'));
    }

    public function test_missing_legacy_owner_refuses_preflight_without_any_schema_change(): void
    {
        $this->user('administrator');
        Target::query()->create([
            'target_id' => 'orphaned-legacy-target',
            'display_name' => 'Legacy',
            'connector_type' => 'wp_ai_bridge',
        ]);
        $migration = require database_path('migrations/2026_11_21_030000_attribute_existing_targets_to_owner.php');
        $migration->down();
        try {
            $migration->up();
            self::fail('Existing Target provenance cannot be guessed without an Owner.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('require an Owner', $exception->getMessage());
        }
        self::assertFalse(Schema::hasColumn('targets', 'created_by_user_id'));
        self::assertFalse(Schema::hasColumn('users', 'self_created_target_access'));
        // Restore the fixture schema so normal RefreshDatabase teardown is not affected.
        DB::table('users')->insert([
            'name' => 'Recovery Owner', 'email' => 'recovery-owner@example.test',
            'password' => 'unusable-test-hash', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $migration->up();
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => $role,
            'email' => uniqid('account-', true).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
        ]);
    }
}
