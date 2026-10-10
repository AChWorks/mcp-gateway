<?php

namespace Tests\Feature\Access;

use App\Application\Access\UserAccessManager;
use App\Application\Targets\TargetInventory;
use App\Domain\Targets\Target;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetInventoryFoundationTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_inventory_is_bounded_and_mixed_connector_neutral(): void
    {
        $user = app(UserAccessManager::class)->create($this->userAttributes('owner'), []);
        $now = now();
        $types = ['wp_ai_bridge', 'ai_server_agent', 'ssh_direct'];
        $rows = [];
        for ($i = 1; $i <= 115; $i++) {
            $rows[] = [
                'id' => (string) Str::ulid(),
                'target_id' => sprintf('target-%04d', $i),
                'display_name' => sprintf('Target %04d', $i),
                'connector_type' => $types[$i % 3],
                'connection_state' => 'disconnected',
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }
        Target::query()->insert($rows);

        DB::flushQueryLog();
        DB::enableQueryLog();
        $first = app(TargetInventory::class)->adminPage($user);
        $logged = DB::getQueryLog();
        DB::disableQueryLog();

        self::assertCount(50, $first['items']);
        self::assertCount(2, $logged);
        self::assertTrue($first['has_more']);
        self::assertSame('target-0001', $first['items'][0]->target_id);
        self::assertSame('target-0050', $first['items'][49]->target_id);
        self::assertSame('ssh_direct', $first['items'][1]->connector_type);

        $cursor = null;
        $result = [];
        do {
            $page = app(TargetInventory::class)->mcpPage($user, $cursor, 37);
            foreach ($page['items'] as $target) {
                $result[] = $target->target_id;
            }
            $cursor = $page['next_cursor'];
        } while ($cursor !== null);

        self::assertCount(115, $result);
        self::assertCount(115, array_unique($result));
        self::assertSame('target-0115', end($result));
        self::assertCount(38, app(TargetInventory::class)->mcpPage($user, connectorType: 'ssh_direct')['items']);
    }

    public function test_inventory_search_never_reveals_out_of_scope_targets(): void
    {
        $user = app(UserAccessManager::class)->create($this->userAttributes('operator'), []);
        $visible = $this->target('server-a');
        $hidden = $this->target('server-b');
        DB::table('user_target_access')->insert([
            'user_id' => $user->id,
            'target_record_id' => $visible->getKey(),
            'allowed' => true,
        ]);

        $inventory = app(TargetInventory::class);
        self::assertSame(['server-a'], array_map(
            static fn (Target $target): string => $target->target_id,
            $inventory->adminPage($user)['items'],
        ));
        self::assertSame([], $inventory->mcpPage($user, search: 'server-b')['items']);
        self::assertCount(1, $inventory->mcpPage($user, search: 'server-')['items']);
        self::assertNotSame($visible->getKey(), $hidden->getKey());
    }

    private function target(string $id): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => 'Server '.$id,
            'connector_type' => 'ssh_direct',
        ]);
    }

    /** @return array{name:string,email:string,password:string,role:string,target_scope_mode:string,access_enabled:bool} */
    private function userAttributes(string $role): array
    {
        return [
            'name' => $role,
            'email' => Str::random(12).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ];
    }
}
