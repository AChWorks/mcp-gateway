<?php

namespace Tests\Feature\Mcp;

use App\Application\Access\UserAccessManager;
use App\Application\Mcp\TargetMcpToolHandlers;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityFeed;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetInventoryMcpTest extends TestCase
{
    use RefreshDatabase;

    public function test_paginated_target_inventory_and_context_are_authorization_filtered_without_remote_details(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $wp = $this->target('a-wp', 'wp_ai_bridge');
        $ssh = $this->target('b-ssh', 'ssh_direct');

        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $wp->getKey(),
            'allowed' => true,
        ]);

        $handlers = app(TargetMcpToolHandlers::class);
        $ownerList = $handlers->targetsList($owner, limit: 1);
        self::assertTrue($ownerList['ok']);
        self::assertCount(1, $ownerList['targets']);
        self::assertSame('a-wp', $ownerList['targets'][0]['target_id']);
        self::assertTrue($ownerList['truncated']);
        self::assertSame('a-wp', $ownerList['next_cursor']);

        $next = $handlers->targetsList($owner, cursor: $ownerList['next_cursor'], limit: 1);
        self::assertSame('b-ssh', $next['targets'][0]['target_id']);
        self::assertNull($next['next_cursor']);
        self::assertFalse($next['truncated']);

        $visible = $handlers->targetsList($operator, search: '-');
        self::assertCount(1, $visible['targets']);
        self::assertSame('a-wp', $visible['targets'][0]['target_id']);
        self::assertArrayNotHasKey('base_url', $visible['targets'][0]);
        self::assertArrayNotHasKey('credential', $visible['targets'][0]);
        self::assertArrayNotHasKey('correlation_id', $visible);
        self::assertSame([], $handlers->targetsList($operator, connector_type: 'ssh_direct')['targets']);

        $context = $handlers->targetContext($operator, 'a-wp');
        self::assertTrue($context['ok']);
        self::assertSame('wp_ai_bridge', $context['target']['connector_type']);
        self::assertSame('disconnected', $context['target']['connection_state']);
        self::assertSame(['target_id', 'display_name', 'connector_type', 'connection_state', 'last_error_code', 'connected_at'],
            array_keys($context['target']));

        $unauthorized = $handlers->targetContext($operator, 'b-ssh');
        self::assertSame($handlers->targetContext($operator, 'unknown-target'), $unauthorized);
        self::assertSame('target_not_found', $unauthorized['error']['code']);
        self::assertArrayNotHasKey('correlation_id', $unauthorized);

        $activity = app(ActivityFeed::class)->page($owner, operation: 'target-context');
        self::assertCount(3, $activity['items']);
        self::assertSame($wp->getKey(), $activity['items'][2]['target_record_id']);
        self::assertNull($activity['items'][0]['target_record_id']);
    }

    public function test_invalid_cursor_and_unavailable_target_never_trigger_network_or_leak_internal_state(): void
    {
        $owner = $this->user('owner');
        $handlers = app(TargetMcpToolHandlers::class);

        self::assertSame('invalid_input', $handlers->targetsList($owner, limit: 0)['error']['code']);
        self::assertSame('invalid_input',
            $handlers->targetsList($owner, cursor: str_repeat('x', 65))['error']['code']);
        self::assertSame('target_not_found', $handlers->targetContext($owner, '../unsafe')['error']['code']);
        self::assertSame('target_not_found', $handlers->targetContext($owner, str_repeat('x', 65))['error']['code']);
    }

    private function user(string $role): User
    {
        return app(UserAccessManager::class)->create([
            'name' => 'MCP '.$role,
            'email' => Str::random(14).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
        ], []);
    }

    private function target(string $id, string $type): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => strtoupper($id),
            'connector_type' => $type,
        ]);
    }
}
