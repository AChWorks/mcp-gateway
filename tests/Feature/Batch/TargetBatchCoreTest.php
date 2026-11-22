<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\BatchProviderResolver;
use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchCoordinator;
use App\Application\Batch\TargetBatchOperationProvider;
use App\Application\Batch\TargetBatchWorker;
use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Models\User;
use Closure;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Tests\TestCase;

final class FakeAuthorizedBatchProvider implements TargetBatchOperationProvider
{
    /** @var list<string> */
    public array $effects = [];

    public bool $fail = false;

    public bool $simulateLostResponse = false;

    public ?Closure $onDispatch = null;

    public ?Closure $afterEffect = null;

    public function key(): string
    {
        return 'ssh.command.run';
    }

    public function connectorType(): string
    {
        return 'ssh_direct';
    }

    public function permission(): GatewayPermission
    {
        return GatewayPermission::SshCommandRun;
    }

    public function isEffectful(): bool
    {
        return true;
    }

    public function validArguments(array $arguments): bool
    {
        return isset($arguments['command']) && is_string($arguments['command'])
            && ($arguments['timeout_seconds'] ?? null) === 10;
    }

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess): array
    {
        if ($this->onDispatch instanceof Closure) {
            ($this->onDispatch)();
        }
        if (! $beforeRemoteEffect()) {
            return ['ok' => false, 'status' => 'blocked', 'error_code' => 'authorization_revoked'];
        }
        $this->effects[] = $target->target_id;
        if ($this->afterEffect instanceof Closure) {
            ($this->afterEffect)();
        }
        if ($this->simulateLostResponse) {
            throw new \RuntimeException('Test: simulated remote effect then lost response');
        }

        return $this->fail
            ? ['ok' => false, 'status' => 'failed', 'error_code' => 'remote_exit_nonzero']
            : ['ok' => true, 'status' => 'completed', 'result' => ['exit_code' => 0, 'target_id' => $target->target_id]];
    }
}

final class FakeBatchProviderResolver implements BatchProviderResolver
{
    public function __construct(public FakeAuthorizedBatchProvider $ssh) {}

    public function find(string $key): ?TargetBatchOperationProvider
    {
        return $key === 'ssh.command.run' ? $this->ssh : null;
    }
}

final class TargetBatchCoreTest extends TestCase
{
    use RefreshDatabase;

    private FakeAuthorizedBatchProvider $fake;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fake = new FakeAuthorizedBatchProvider;
        $this->app->instance(BatchProviderResolver::class, new FakeBatchProviderResolver($this->fake));
        config()->set('batch.max_parallelism', 12);
        config()->set('batch.global_active', 12);
        config()->set('batch.user_active', 12);
    }

    public function test_explicit_preview_durable_queue_idempotent_request_and_sequential_worker_completion(): void
    {
        $user = $this->owner();
        $targets = $this->targets(3);
        $origin = $this->web($user);
        $core = app(TargetBatchCoordinator::class);
        $ids = array_map(static fn (Target $t): string => $t->target_id, $targets);
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids, ['command' => 'uptime', 'timeout_seconds' => 10], 'rolling', false, 3);
        self::assertSame(3, $preview['eligible_count']);
        self::assertTrue($preview['effectful']);
        self::assertCount(3, $preview['items']);
        self::assertSame([], $this->fake->effects);
        $request = (string) Str::uuid();
        $created = $core->create($user, $origin, $request, 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], $preview['preview_token'], 'rolling', false, 3);
        $id = $created['batch_id'];
        self::assertSame('queued', $created['status']);
        self::assertSame(3, DB::table('target_batch_items')->where('batch_id', $id)->count());
        self::assertNotEquals('uptime', DB::table('target_batches')->where('id', $id)->value('arguments_ciphertext'));
        self::assertSame($id, $core->create($user, $origin, $request, 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], $preview['preview_token'], 'rolling', false, 3)['batch_id']);
        self::assertSame(1, DB::table('target_batches')->count());

        $worker = app(TargetBatchWorker::class);
        foreach ($ids as $expected) {
            $worked = $worker->workOnce();
            self::assertSame($expected, $worked['target_id']);
            self::assertSame('completed', $worked['status']);
            self::assertNull($worked['error_code']);
        }
        self::assertNull($worker->workOnce());
        self::assertSame($ids, $this->fake->effects);
        $status = $core->status($user, $origin, $id);
        self::assertSame('completed', $status['status']);
        self::assertSame(3, $status['counts']['completed']);
        self::assertSame(0, $status['items'][0]['result']['result']['exit_code']);
        self::assertSame($id, $core->list($user, $origin)['batches'][0]['batch_id']);
        $this->expectException(InvalidArgumentException::class);
        $core->create($user, $origin, $request, 'ssh.command.run', $ids,
            ['command' => 'different', 'timeout_seconds' => 10], $preview['preview_token'], 'rolling', false, 3);
    }

    public function test_original_request_id_recovers_after_preview_expires_and_target_access_or_binding_changes(): void
    {
        $user = $this->owner();
        $targets = $this->targets(1);
        $ids = [$targets[0]->target_id];
        $origin = $this->web($user);
        $core = app(TargetBatchCoordinator::class);
        $arguments = ['command' => 'uptime', 'timeout_seconds' => 10];
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids, $arguments);
        $requestId = (string) Str::uuid();
        $created = $core->create($user, $origin, $requestId, 'ssh.command.run',
            $ids, $arguments, $preview['preview_token']);
        $this->travel(11)->minutes();
        DB::table('ssh_direct_target_configs')
            ->where('target_record_id', $targets[0]->getKey())
            ->update(['host' => 'another-host.example.test']);
        // Ownership of the original queued result remains visible while new
        // effects cannot pass current authorization or binding checks.
        $user->forceFill(['role' => 'operator', 'target_scope_mode' => 'selected'])->save();
        $recovered = $core->create($user, $origin, $requestId, 'ssh.command.run',
            $ids, $arguments, $preview['preview_token']);
        self::assertSame($created['batch_id'], $recovered['batch_id']);
        self::assertSame(1, DB::table('target_batches')->count());
        self::assertSame([], $this->fake->effects);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('different original Batch input');
        $core->create($user, $origin, $requestId, 'ssh.command.run',
            $ids, ['command' => 'id', 'timeout_seconds' => 10], $preview['preview_token']);
    }

    public function test_revoked_actor_cannot_recover_existing_request_even_with_old_preview_token(): void
    {
        $user = $this->owner();
        $targets = $this->targets(1);
        $origin = $this->web($user);
        $core = app(TargetBatchCoordinator::class);
        $ids = [$targets[0]->target_id];
        $arguments = ['command' => 'uptime', 'timeout_seconds' => 10];
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids, $arguments);
        $request = (string) Str::uuid();
        $core->create($user, $origin, $request, 'ssh.command.run', $ids, $arguments, $preview['preview_token']);
        $user->forceFill(['access_enabled' => false])->save();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not readable');
        $core->create($user, $origin, $request, 'ssh.command.run', $ids, $arguments, $preview['preview_token']);
    }

    public function test_late_success_after_another_worker_reconciles_expired_lease_never_claims_success(): void
    {
        $user = $this->owner();
        $targets = $this->targets(1);
        $origin = $this->web($user);
        $batchId = $this->create($user, $origin, $targets);
        $this->fake->afterEffect = static function () use ($batchId): void {
            DB::table('target_batch_items')->where('batch_id', $batchId)->update([
                'lease_expires_at' => now()->subMinute(),
            ]);
            // A separately constructed Worker reconciles the first claim while
            // its remote call is still holding the successful response.
            self::assertNull(app(TargetBatchWorker::class)->workOnce());
        };
        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('outcome_unknown', $worked['status']);
        self::assertSame('dispatch_lease_expired', $worked['error_code']);
        self::assertSame('outcome_unknown', DB::table('target_batch_items')->where('batch_id', $batchId)->value('status'));
        self::assertSame('outcome_unknown', DB::table('target_batches')->where('id', $batchId)->value('status'));
        self::assertSame([$targets[0]->target_id], $this->fake->effects);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
        $events = DB::table('activity_events')->where('operation', 'like', 'target-batch%')
            ->orderBy('id')->get();
        self::assertSame(1, $events->count());
        self::assertSame('unknown', $events[0]->outcome);
        self::assertSame('late_result_ignored', $events[0]->error_code);
        $details = json_decode((string) $events[0]->diagnostic_context, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame($batchId, $details['batch_id']);
        self::assertSame('outcome_unknown', $details['authoritative_status']);
        self::assertSame('completed', $details['late_provider_status']);
        self::assertTrue($details['late_response_after_lease']);
        self::assertSame((string) $events[0]->correlation_id, $worked['diagnostic_reference']);
    }

    public function test_historical_mcp_request_recovers_under_new_consent_and_profile_generation_without_dispatch(): void
    {
        $user = $this->owner();
        $target = $this->targets(1)[0];
        $clientId = (string) config('oauth.client.id');
        $resource = (string) config('oauth.resource');
        $store = app(OAuthAuthorizationStore::class);
        $profiles = app(ClientProfileRegistry::class);
        $originalAuthorization = $store->approve((int) $user->getKey(), $clientId, $resource, ['mcp']);

        $origin = static fn (string $authorizationId, int $generation): array => [
            'source_channel' => 'mcp',
            'client_id' => $clientId,
            'client_identity_hash' => hash('sha256', 'chatgpt'."\0".$clientId),
            'client_profile_key' => 'chatgpt',
            'client_profile_generation' => $generation,
            'authorization_id' => $authorizationId,
            'resource_hash' => hash('sha256', $resource),
        ];
        $firstOrigin = $origin($originalAuthorization, 1);
        $core = app(TargetBatchCoordinator::class);
        $ids = [$target->target_id];
        $args = ['command' => 'uptime', 'timeout_seconds' => 10];
        $requestId = (string) Str::uuid();
        $preview = $core->preview($user, $firstOrigin, 'ssh.command.run', $ids, $args);
        $created = $core->create($user, $firstOrigin, $requestId, 'ssh.command.run',
            $ids, $args, $preview['preview_token']);
        $batchId = $created['batch_id'];

        DB::table('oauth_authorizations')->where('id', $originalAuthorization)
            ->update(['revoked_at' => now()]);
        try {
            $core->create($user, $firstOrigin, $requestId, 'ssh.command.run',
                $ids, $args, $preview['preview_token']);
            self::fail('Revoked original OAuth consent must not grant current read access.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('not readable', $exception->getMessage());
        }

        $secondAuthorization = $store->approve((int) $user->getKey(), $clientId, $resource, ['mcp']);
        self::assertNotSame($originalAuthorization, $secondAuthorization);
        $secondOrigin = $origin($secondAuthorization, 1);
        self::assertSame($batchId, $core->status($user, $secondOrigin, $batchId)['batch_id']);
        self::assertSame($batchId, $core->list($user, $secondOrigin)['batches'][0]['batch_id']);
        // A lost reply is recoverable with an obsolete Preview; recovering
        // existing input must not revalidate original Dispatch authorization.
        self::assertSame($batchId, $core->create($user, $secondOrigin, $requestId,
            'ssh.command.run', $ids, $args, 'expired-original-preview')['batch_id']);
        self::assertSame(1, DB::table('target_batches')->count());
        self::assertSame($originalAuthorization, DB::table('target_batches')
            ->where('id', $batchId)->value('authorization_id'));

        // Rotating the Client profile is an explicit revoke+enable lifecycle.
        // New generation's valid consent may READ old status but cannot
        // authorize the still-queued effect admitted under the old generation.
        $profiles->disable('chatgpt');
        $profiles->enable('chatgpt');
        $thirdAuthorization = $store->approve((int) $user->getKey(), $clientId, $resource, ['mcp']);
        self::assertNotSame($secondAuthorization, $thirdAuthorization);
        self::assertSame(2, $profiles->active($clientId)['generation']);
        $current = $origin($thirdAuthorization, 2);
        self::assertSame($batchId, $core->status($user, $current, $batchId)['batch_id']);
        self::assertSame($batchId, $core->create($user, $current, $requestId,
            'ssh.command.run', $ids, $args, 'expired-original-preview')['batch_id']);
        self::assertSame(1, DB::table('target_batches')->count());
        self::assertSame(1, (int) DB::table('target_batches')
            ->where('id', $batchId)->value('client_profile_generation'));
        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('blocked', $worked['status']);
        self::assertSame('authorization_revoked', $worked['error_code']);
        self::assertSame([], $this->fake->effects);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());

        // Current intent and read authority must remain exact. New Client,
        // profile, User or resource context cannot read this historical Batch.
        foreach ([
            [...$current, 'client_id' => 'unrelated-client',
                'client_identity_hash' => hash('sha256', 'chatgpt'."\0".'unrelated-client')],
            [...$current, 'client_id' => 'forged-client-with-old-hash'],
            [...$current, 'client_profile_key' => 'another-profile',
                'client_identity_hash' => hash('sha256', 'another-profile'."\0".$clientId)],
            [...$current, 'resource_hash' => str_repeat('0', 64)],
        ] as $wrong) {
            try {
                $core->create($user, $wrong, $requestId, 'ssh.command.run',
                    $ids, $args, 'expired-original-preview');
                self::fail('Foreign or invalid current MCP origin must not recover Batch history.');
            } catch (InvalidArgumentException $exception) {
                self::assertNotEmpty($exception->getMessage());
            }
        }
        $other = $this->owner();
        try {
            $core->status($other, $current, $batchId);
            self::fail('Different User must not see historical Batch.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('not authorized', $exception->getMessage());
        }
        try {
            $core->create($user, $current, $requestId, 'ssh.command.run',
                $ids, ['command' => 'id', 'timeout_seconds' => 10], 'expired-original-preview');
            self::fail('Same request ID cannot change original operation.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('different original Batch input', $exception->getMessage());
        }
        try {
            $core->create($user, $current, (string) Str::uuid(), 'ssh.command.run',
                $ids, $args, 'expired-original-preview');
            self::fail('Historical recovery must never authorize a new Batch admission.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('preview', strtolower($exception->getMessage()));
        }
        self::assertSame(1, DB::table('target_batches')->count());
        $user->forceFill(['ai_access_enabled' => false])->save();
        try {
            $core->create($user, $current, $requestId, 'ssh.command.run',
                $ids, $args, 'expired-original-preview');
            self::fail('Disabled AI access cannot read historical MCP Batch.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('not readable', $exception->getMessage());
        }
        self::assertSame([], $this->fake->effects);
    }

    public function test_deferred_nonowner_mcp_diagnostics_preserve_actor_and_client_without_cross_client_access(): void
    {
        $operator = $this->owner();
        $operator->forceFill(['role' => 'operator', 'target_scope_mode' => 'selected'])->save();
        $target = $this->targets(1)[0];
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);
        $clientId = (string) config('oauth.client.id');
        $authorization = (string) Str::ulid();
        DB::table('oauth_authorizations')->insert([
            'id' => $authorization, 'user_id' => $operator->getKey(),
            'client_id' => $clientId, 'resource' => (string) config('oauth.resource'),
            'resource_hash' => hash('sha256', (string) config('oauth.resource')),
            'scopes' => json_encode([(string) config('oauth.scope')], JSON_THROW_ON_ERROR),
            'client_profile_key' => 'chatgpt', 'client_profile_generation' => 1,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $origin = [
            'source_channel' => 'mcp', 'client_id' => $clientId,
            'client_identity_hash' => hash('sha256', 'chatgpt'."\0".$clientId),
            'client_profile_key' => 'chatgpt', 'client_profile_generation' => 1,
            'authorization_id' => $authorization,
            'resource_hash' => hash('sha256', (string) config('oauth.resource')),
        ];
        $core = app(TargetBatchCoordinator::class);
        $args = ['command' => 'uptime', 'timeout_seconds' => 10];
        $preview = $core->preview($operator, $origin, 'ssh.command.run', [$target->target_id], $args);
        self::assertSame(1, $preview['eligible_count']);
        $requestId = (string) Str::uuid();
        $created = $core->create($operator, $origin, $requestId, 'ssh.command.run',
            [$target->target_id], $args, $preview['preview_token']);
        $otherClient = [
            ...$origin, 'client_id' => 'another-client.example.test',
            'client_identity_hash' => hash('sha256', 'chatgpt'."\0".'another-client.example.test'),
        ];
        try {
            $core->status($operator, $otherClient, $created['batch_id']);
            self::fail('A different MCP Client must not recover another client\'s Batch.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('not authorized', $exception->getMessage());
        }
        try {
            $core->create($operator, $otherClient, $requestId, 'ssh.command.run',
                [$target->target_id], $args, $preview['preview_token']);
            self::fail('Original client Preview cannot authorize a new other-client Batch.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('authorization', $exception->getMessage());
        }
        self::assertSame(1, DB::table('target_batches')->count());
        // Actual worker runs with no HTTP request and a failed provider, not
        // a fabricated request principal impersonating the original client.
        $this->fake->fail = true;
        $completed = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('failed', $completed['status']);
        $event = DB::table('activity_events')
            ->where('correlation_id', $completed['diagnostic_reference'])->first();
        self::assertNotNull($event);
        self::assertSame('oauth_user', $event->actor_type);
        self::assertSame((string) $operator->getKey(), $event->actor_id);
        self::assertSame(hash('sha256', $clientId), $event->client_id_hash);
        self::assertSame('chatgpt', $event->client_profile_key);
        $details = json_decode((string) $event->diagnostic_context, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame($created['batch_id'], $details['batch_id']);
        self::assertSame('mcp', $details['source_channel']);
        self::assertSame('failed', $details['batch_status']);
        self::assertNotEmpty($details['batch_child_id']);
        self::assertTrue(Str::isUuid($details['attempt_id']));

        $reader = app(OperationDiagnosticsMcpToolHandlers::class);
        $matching = $reader->read($operator, $completed['diagnostic_reference'], null, 1, $clientId, 'chatgpt');
        self::assertTrue($matching['ok'], json_encode($matching, JSON_THROW_ON_ERROR));
        self::assertSame('remote_exit_nonzero', $matching['events'][0]['error_code']);
        self::assertSame($created['batch_id'], $matching['events'][0]['diagnostics']['batch_id']);
        self::assertFalse($reader->read($operator, $completed['diagnostic_reference'], null, 1,
            'different-oauth-client', 'chatgpt')['ok']);
        self::assertFalse($reader->read($operator, $completed['diagnostic_reference'], null, 1,
            $clientId, 'different-profile')['ok']);
        $other = $this->owner();
        $other->forceFill(['role' => 'operator', 'target_scope_mode' => 'selected'])->save();
        DB::table('user_target_access')->insert([
            'user_id' => $other->getKey(), 'target_record_id' => $target->getKey(), 'allowed' => true,
        ]);
        self::assertFalse($reader->read($other, $completed['diagnostic_reference'], null, 1,
            $clientId, 'chatgpt')['ok']);
        self::assertSame([$target->target_id], $this->fake->effects);
    }

    public function test_cancel_prevents_unstarted_effects_without_false_remote_cancellation_claim(): void
    {
        $user = $this->owner();
        $targets = $this->targets(2);
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $targets);
        $outcome = app(TargetBatchCoordinator::class)->cancel($user, $origin, $id);
        self::assertSame('canceled', $outcome['status']);
        self::assertSame(2, $outcome['counts']['canceled']);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
        self::assertSame([], $this->fake->effects);
    }

    public function test_revoked_user_and_changed_host_binding_are_rechecked_before_each_deferred_effect(): void
    {
        $user = $this->owner();
        $targets = $this->targets(2);
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $targets);
        $user->forceFill(['access_enabled' => false])->save();
        $first = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('blocked', $first['status']);
        self::assertSame('authorization_revoked', $first['error_code']);
        $user->forceFill(['access_enabled' => true])->save();
        DB::table('ssh_direct_target_configs')->where('target_record_id', $targets[1]->getKey())->update([
            'host' => 'rotated.example.test',
        ]);
        $second = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('blocked', $second['status']);
        self::assertSame([], $this->fake->effects);
        self::assertSame('failed', app(TargetBatchCoordinator::class)->status($user, $origin, $id)['status']);
    }

    public function test_mid_dispatch_revocation_blocks_effect_and_an_uncertain_lost_response_is_never_replayed(): void
    {
        $user = $this->owner();
        $targets = $this->targets(2);
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $targets);
        $this->fake->onDispatch = static function () use ($user): void {
            $user->forceFill(['access_enabled' => false])->save();
        };
        self::assertSame('blocked', app(TargetBatchWorker::class)->workOnce()['status']);
        self::assertSame([], $this->fake->effects);
        $user->forceFill(['access_enabled' => true])->save();
        $this->fake->onDispatch = null;
        $this->fake->simulateLostResponse = true;
        $second = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('outcome_unknown', $second['status']);
        self::assertSame([$targets[1]->target_id], $this->fake->effects);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
        self::assertSame('outcome_unknown', app(TargetBatchCoordinator::class)->status($user, $origin, $id)['status']);
    }

    public function test_missing_global_admission_lock_fails_closed_without_remote_effect(): void
    {
        $user = $this->owner();
        $targets = $this->targets(1);
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $targets);
        DB::table('operational_settings')->where('id', 1)->delete();
        try {
            app(TargetBatchWorker::class)->workOnce();
            self::fail('A missing global admission lock must not permit any remote Batch dispatch.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('admission lock is unavailable', $exception->getMessage());
        }
        self::assertSame([], $this->fake->effects);
        self::assertSame('queued', DB::table('target_batch_items')->where('batch_id', $id)->value('status'));
    }

    public function test_expired_in_flight_lease_becomes_unknown_without_dispatch_again(): void
    {
        $user = $this->owner();
        $targets = $this->targets(1);
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $targets);
        DB::table('target_batch_items')->where('batch_id', $id)->update([
            'status' => 'dispatching', 'dispatch_attempt_id' => (string) Str::uuid(),
            'lease_expires_at' => now()->subMinute(),
        ]);
        DB::table('target_batches')->where('id', $id)->update(['status' => 'running']);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
        self::assertSame('outcome_unknown', DB::table('target_batch_items')->where('batch_id', $id)->value('status'));
        self::assertSame('outcome_unknown', DB::table('target_batches')->where('id', $id)->value('status'));
        self::assertSame([], $this->fake->effects);
    }

    public function test_stop_on_failure_blocks_next_rolling_child(): void
    {
        $user = $this->owner();
        $targets = $this->targets(3);
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $targets, stopOnFailure: true);
        $this->fake->fail = true;
        self::assertSame('failed', app(TargetBatchWorker::class)->workOnce()['status']);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
        $status = app(TargetBatchCoordinator::class)->status($user, $origin, $id);
        self::assertSame('failed', $status['status']);
        self::assertSame(2, $status['counts']['blocked']);
        self::assertSame([$targets[0]->target_id], $this->fake->effects);
    }

    public function test_selected_operator_preview_matches_canonical_grants_and_explicit_denials(): void
    {
        $operator = $this->owner();
        $operator->forceFill(['role' => 'operator', 'target_scope_mode' => 'selected'])->save();
        $targets = $this->targets(3);
        foreach (array_slice($targets, 0, 2) as $target) {
            DB::table('user_target_access')->insert([
                'user_id' => $operator->getKey(),
                'target_record_id' => $target->getKey(),
                'allowed' => true,
            ]);
        }
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $targets[1]->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);
        $ids = array_map(static fn (Target $target): string => $target->target_id, $targets);
        $preview = app(TargetBatchCoordinator::class)->preview(
            $operator, $this->web($operator), 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], 'concurrent', false, 2,
        );
        self::assertSame(1, $preview['eligible_count']);
        self::assertSame('queued', $preview['items'][0]['status']);
        self::assertSame('blocked', $preview['items'][1]['status']);
        self::assertSame('blocked', $preview['items'][2]['status']);
        self::assertNull($preview['items'][1]['target_record_id']);
        self::assertNull($preview['items'][2]['target_record_id']);
        self::assertSame([], $this->fake->effects);
    }

    public function test_preview_batches_credential_and_config_io_instead_of_n_plus_one_target_queries(): void
    {
        $user = $this->owner();
        $targets = $this->targets(24);
        $ids = array_map(static fn (Target $target): string => $target->target_id, $targets);
        DB::flushQueryLog();
        DB::enableQueryLog();
        try {
            $preview = app(TargetBatchCoordinator::class)->preview(
                $user, $this->web($user), 'ssh.command.run', $ids,
                ['command' => 'uptime', 'timeout_seconds' => 10], 'concurrent', false, 4,
            );
            $queryCount = count(DB::getQueryLog());
        } finally {
            DB::disableQueryLog();
            DB::flushQueryLog();
        }
        self::assertSame(24, $preview['eligible_count']);
        self::assertLessThan(15, $queryCount,
            'Preview must use bounded selection/config/credential queries rather than one set per Target.');
        self::assertCount(24, $preview['items']);
        self::assertSame([], $this->fake->effects);
    }

    public function test_preview_does_not_disclose_unknown_or_denied_target_records(): void
    {
        $user = $this->owner();
        $targets = $this->targets(1);
        $origin = $this->web($user);
        $preview = app(TargetBatchCoordinator::class)->preview($user, $origin,
            'ssh.command.run', [$targets[0]->target_id, 'does-not-exist'],
            ['command' => 'uptime', 'timeout_seconds' => 10]);
        self::assertSame(1, $preview['eligible_count']);
        self::assertSame('blocked', $preview['items'][1]['status']);
        self::assertNull($preview['items'][1]['target_record_id']);
        self::assertSame('target_not_found', $preview['items'][1]['error_code']);
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Batch Owner', 'email' => uniqid('batch-', true).'@example.test',
            'password' => 'CorrectHorse!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
    }

    /** @return list<Target> */
    private function targets(int $count): array
    {
        $items = [];
        for ($i = 0; $i < $count; $i++) {
            $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(60 + $i), 32));
            $target = app(SshTargetRegistration::class)->register(
                'batch-host-'.$i, 'Batch Host '.$i, 'batch-'.$i.'.example.test', 22,
                'batchuser', $pin, 'password', 'test-password', null,
            );
            $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
            $items[] = $target;
        }

        return $items;
    }

    /** @return array<string,mixed> */
    private function web(User $user): array
    {
        $request = Request::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);

        return app(DeferredBatchAuthority::class)->captureWeb($user, $request);
    }

    /** @param list<Target> $targets
     * @param  array<string,mixed>  $origin
     */
    private function create(User $user, array $origin, array $targets, bool $stopOnFailure = false): string
    {
        $core = app(TargetBatchCoordinator::class);
        $ids = array_map(static fn (Target $target): string => $target->target_id, $targets);
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], 'rolling', $stopOnFailure, 1);

        return $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], $preview['preview_token'],
            'rolling', $stopOnFailure, 1)['batch_id'];
    }
}
