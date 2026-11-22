<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/** Fresh v3 has explicit Target provenance, no historical owner inference. */
final class SelfCreatedTargetAttributionMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_v3_stores_explicit_creator_without_guessing_an_owner_or_materializing_access_grants(): void
    {
        $owner = $this->user('owner');
        $creator = $this->user('administrator');
        $target = new Target([
            'target_id' => 'new-v3-wordpress', 'display_name' => 'New Target',
            'connector_type' => 'wp_ai_bridge',
        ]);
        $target->forceFill(['created_by_user_id' => $creator->getKey()])->save();

        self::assertTrue(Schema::hasColumn('targets', 'created_by_user_id'));
        self::assertSame($creator->getKey(), $target->fresh()->created_by_user_id);
        self::assertNotSame($owner->getKey(), $target->fresh()->created_by_user_id);
        self::assertSame(0, DB::table('user_target_access')->count());
        self::assertFalse((bool) $creator->self_created_target_access);
        self::assertFalse(app(AccessControl::class)->allows($creator, GatewayPermission::TargetsView, $target));
    }

    public function test_v3_targets_without_provenance_are_not_reassigned_or_auto_granted(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $target = Target::query()->create([
            'target_id' => 'unclaimed-target', 'display_name' => 'Unclaimed',
            'connector_type' => 'ssh_direct',
        ]);
        self::assertNull($target->fresh()->created_by_user_id);
        self::assertFalse((bool) DB::table('users')->where('id', $owner->id)
            ->value('self_created_target_access'));
        self::assertFalse((bool) DB::table('users')->where('id', $operator->id)
            ->value('self_created_target_access'));
        self::assertFalse(app(AccessControl::class)->allows($operator, GatewayPermission::TargetsView, $target));
        self::assertSame(0, DB::table('user_target_access')->count());
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
