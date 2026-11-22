<?php

namespace Tests\Feature\Batch;

use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\TargetConnectionState;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetBatchWebAdmissionTest extends TestCase
{
    use RefreshDatabase;

    public function test_browser_requires_authenticated_local_session_before_preview_or_create(): void
    {
        $this->postJson('/admin/target-batches/preview', [
            'capability' => 'ssh.command.run', 'target_ids' => ['never-known'],
            'arguments' => ['command' => 'id', 'timeout_seconds' => 10],
        ])->assertUnauthorized();
        $this->postJson('/admin/target-batches', [
            'capability' => 'ssh.command.run', 'target_ids' => ['never-known'],
            'arguments' => ['command' => 'id', 'timeout_seconds' => 10],
            'request_id' => (string) Str::uuid(), 'preview_token' => '1.aaa',
        ])->assertUnauthorized();
    }

    public function test_session_preview_run_status_cancel_are_bound_to_same_human_and_target(): void
    {
        $owner = $this->user('owner');
        $target = $this->target();
        $plan = [
            'capability' => 'ssh.command.run', 'target_ids' => [$target],
            'arguments' => ['command' => 'printf BatchWeb', 'timeout_seconds' => 10],
            'execution_mode' => 'rolling', 'parallelism' => 1,
        ];
        $this->actingAs($owner);
        $preview = $this->postJson('/admin/target-batches/preview', $plan)
            ->assertOk()->assertJsonPath('eligible_count', 1);
        $token = $preview->json('preview_token');
        self::assertIsString($token);
        $request = (string) Str::uuid();
        $created = $this->postJson('/admin/target-batches', [...$plan,
            'request_id' => $request, 'preview_token' => $token,
        ])->assertOk()->assertJsonPath('status', 'queued');
        $id = $created->json('batch_id');
        self::assertIsString($id);
        $this->postJson('/admin/target-batches', [...$plan,
            'request_id' => $request, 'preview_token' => $token,
        ])->assertJsonPath('batch_id', $id);
        $this->getJson('/admin/target-batches/'.$id)->assertOk()
            ->assertJsonPath('items.0.target_id', $target);
        $this->getJson('/admin/target-batches')->assertOk()
            ->assertJsonPath('batches.0.batch_id', $id);

        $other = $this->user('operator');
        $this->actingAs($other);
        $this->getJson('/admin/target-batches/'.$id)->assertUnprocessable();
        $this->postJson('/admin/target-batches/'.$id.'/cancel')->assertUnprocessable();
        $this->getJson('/admin/target-batches')->assertJsonCount(0, 'batches');
        $this->actingAs($owner);
        $this->postJson('/admin/target-batches/'.$id.'/cancel')
            ->assertOk()->assertJsonPath('status', 'canceled');
        $this->getJson('/admin/target-batches/'.$id)->assertJsonPath('items.0.status', 'canceled');
    }

    public function test_browser_rejects_forged_origins_unsupported_wordpress_publish_and_stale_preview(): void
    {
        $this->actingAs($this->user('owner'));
        $this->postJson('/admin/target-batches/preview', [
            'capability' => 'wordpress.content.publish', 'target_ids' => ['no-target'],
            'arguments' => ['post' => ['title' => 'not permitted']],
        ])->assertUnprocessable();
        $this->postJson('/admin/target-batches/preview', [
            'capability' => 'ssh.command.run', 'target_ids' => ['no-target'],
            'arguments' => ['command' => 'id', 'timeout_seconds' => 10],
            'source_channel' => 'mcp', 'client_id' => 'forged-client',
        ])->assertOk()->assertJsonPath('items.0.status', 'blocked');
        $target = $this->target();
        $plan = [
            'capability' => 'ssh.command.run', 'target_ids' => [$target],
            'arguments' => ['command' => 'id', 'timeout_seconds' => 10],
        ];
        $preview = $this->postJson('/admin/target-batches/preview', $plan)->assertOk();
        $this->postJson('/admin/target-batches', [...$plan,
            'arguments' => ['command' => 'different', 'timeout_seconds' => 10],
            'request_id' => (string) Str::uuid(),
            'preview_token' => $preview->json('preview_token'),
        ])->assertUnprocessable()->assertJsonPath('error.code', 'batch_not_admitted');
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => 'Batch '.$role, 'email' => uniqid('batch-web-', true).'@example.test',
            'password' => 'StrongPassword!234', 'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
    }

    private function target(): string
    {
        $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(57), 32));
        $target = app(SshTargetRegistration::class)->register(
            'batch-web-host', 'Batch Web Host', 'web.example.test', 22,
            'batch', $pin, 'password', 'fixture-only', null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target->target_id;
    }
}
