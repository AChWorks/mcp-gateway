<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class AccessControlTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_has_recoverable_full_access_to_every_site(): void
    {
        $owner = $this->user(GatewayRole::Owner, TargetScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_permission_denials')->insert([
            'user_id' => $owner->id,
            'permission' => GatewayPermission::TargetsRemove->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $owner->id,
            'target_record_id' => $alpha->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertTrue($access->allows($owner, GatewayPermission::TargetsRemove, $alpha));
        self::assertTrue($access->allows($owner, GatewayPermission::SecurityManage, $beta));
        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeTargets(Target::query(), $owner)->orderBy('target_id')->pluck('target_id')->all(),
        );
    }

    public function test_selected_operator_scope_and_per_site_denials_only_narrow_authority(): void
    {
        $operator = $this->user(GatewayRole::Operator, TargetScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $gamma = $this->site('gamma');

        foreach ([$alpha, $beta] as $site) {
            DB::table('user_target_access')->insert([
                'user_id' => $operator->id,
                'target_record_id' => $site->id,
                'allowed' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->id,
            'target_record_id' => $alpha->id,
            'permission' => GatewayPermission::WordpressAbilitiesExecuteMutating->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertTrue($access->allows($operator, GatewayPermission::TargetsView, $alpha));
        self::assertTrue($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteReadonly, $alpha));
        self::assertFalse($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteMutating, $alpha));
        self::assertTrue($access->allows($operator, GatewayPermission::WordpressAbilitiesExecuteMutating, $beta));
        self::assertFalse($access->allows($operator, GatewayPermission::TargetsRemove, $beta));
        self::assertFalse($access->allows($operator, GatewayPermission::TargetsView, $gamma));

        self::assertSame(
            ['alpha', 'beta'],
            $access->scopeTargets(Target::query(), $operator)->orderBy('target_id')->pluck('target_id')->all(),
        );
    }

    public function test_all_site_scope_can_exclude_one_site_and_global_denials_apply_everywhere(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, TargetScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_target_access')->insert([
            'user_id' => $administrator->id,
            'target_record_id' => $beta->id,
            'allowed' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('user_permission_denials')->insert([
            'user_id' => $administrator->id,
            'permission' => GatewayPermission::TargetsDisconnect->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertTrue($access->allows($administrator, GatewayPermission::TargetsView, $alpha));
        self::assertFalse($access->allows($administrator, GatewayPermission::TargetsView, $beta));
        self::assertFalse($access->allows($administrator, GatewayPermission::TargetsDisconnect, $alpha));
        self::assertSame(
            ['alpha'],
            $access->scopeTargets(Target::query(), $administrator)->pluck('target_id')->all(),
        );
    }

    public function test_site_remove_applies_to_any_site_in_effective_scope_not_creation_ownership(): void
    {
        $administrator = $this->user(GatewayRole::Administrator, TargetScopeMode::Selected);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        DB::table('user_target_access')->insert([
            'user_id' => $administrator->id,
            'target_record_id' => $beta->id,
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $access = app(AccessControl::class);

        self::assertFalse($access->allows($administrator, GatewayPermission::TargetsRemove, $alpha));
        self::assertTrue($access->allows($administrator, GatewayPermission::TargetsRemove, $beta));
    }

    public function test_disabled_user_is_denied_even_when_role_and_scope_would_allow_access(): void
    {
        $viewer = $this->user(GatewayRole::Viewer, TargetScopeMode::All, false);
        $site = $this->site('alpha');

        $access = app(AccessControl::class);

        self::assertFalse($access->allows($viewer, GatewayPermission::TargetsView, $site));
        self::assertSame(0, $access->scopeTargets(Target::query(), $viewer)->count());
    }

    private function user(
        GatewayRole $role,
        TargetScopeMode $scope,
        bool $enabled = true,
    ): User {
        return User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'target_scope_mode' => $scope->value,
            'access_enabled' => $enabled,
        ]);
    }

    private function site(string $siteId): Target
    {
        return Target::query()->create([
            'target_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'connector_type' => 'wp_ai_bridge',
            'connection_state' => 'connected',
        ]);
    }
}
