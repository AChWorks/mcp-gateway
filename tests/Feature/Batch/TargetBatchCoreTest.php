<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\BatchProviderResolver;
use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchBinding;
use App\Application\Batch\TargetBatchCoordinator;
use App\Application\Batch\TargetBatchOperationProvider;
use App\Application\Batch\TargetBatchWorker;
use App\Application\Mcp\OperationDiagnosticsMcpToolHandlers;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\SshVerificationState;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetTransportBinding;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Activity\ActivityAttribution;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Models\User;
use Carbon\Carbon;
use Closure;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
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

    public int $remoteSeconds = 10;

    public ?Closure $onDispatch = null;

    public ?Closure $afterEffect = null;

    public ?Closure $duringAdmission = null;

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

    public function remoteTimeoutSeconds(array $arguments): int
    {
        return $this->remoteSeconds;
    }

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess, Closure $admitRemoteEffect, ActivityAttribution $attribution): array
    {
        if ($this->onDispatch instanceof Closure) {
            ($this->onDispatch)();
        }
        if (! $beforeRemoteEffect() || ! $admitRemoteEffect($this->duringAdmission ?? static function (): void {})) {
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

    public function test_owner_batch_limits_restrict_new_plans_and_worker_defaults_without_losing_queue(): void
    {
        $user = $this->owner();
        $targets = $this->targets(3);
        $origin = $this->web($user);
        $ids = array_map(static fn (Target $target): string => $target->target_id, $targets);
        DB::table('operational_settings')->where('id', 1)->update([
            'batch_max_parallelism' => 2, 'batch_global_active' => 1,
            'batch_user_active' => 1, 'batch_worker_max_children' => 1,
            'batch_worker_max_seconds' => 60,
        ]);

        $core = app(TargetBatchCoordinator::class);
        try {
            $core->preview($user, $origin, 'ssh.command.run', $ids,
                ['command' => 'uptime', 'timeout_seconds' => 10], 'concurrent', false, 3);
            self::fail('A Batch must not use a larger concurrency than the current Owner setting.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('parallelism', $exception->getMessage());
        }

        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], 'concurrent', false, 2);
        $batch = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run', $ids,
            ['command' => 'uptime', 'timeout_seconds' => 10], $preview['preview_token'], 'concurrent', false, 2);
        self::assertSame('queued', $batch['status']);
        $this->artisan('gateway:batch-work')->assertSuccessful();
        self::assertSame(1, count($this->fake->effects),
            'An Owner-configured one-child worker invocation must not drain all queued Targets.');
        self::assertSame(2, DB::table('target_batch_items')->where('status', 'queued')->count());
        $this->artisan('gateway:batch-work')->assertSuccessful();
        self::assertSame(2, count($this->fake->effects));
        $this->artisan('gateway:batch-work')->assertSuccessful();
        self::assertSame('completed', $core->status($user, $origin, $batch['batch_id'])['status']);
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
        $child = DB::table('target_batch_items')->where('batch_id', $batchId)->sole();
        self::assertTrue((bool) $child->effect_admitted);
        self::assertNull($child->result_ciphertext);
        $late = json_decode(Crypt::decryptString($child->late_observation_ciphertext), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame($child->dispatch_attempt_id, $late['attempt_id']);
        self::assertSame($worked['diagnostic_reference'], $late['diagnostic_reference']);
        self::assertSame('completed', $late['observation']['status']);
        self::assertSame(0, $late['observation']['result']['exit_code']);
        self::assertSame($targets[0]->target_id, $late['observation']['result']['target_id']);
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

    public function test_same_grant_reseal_preserves_queued_work_but_superseded_grant_fences_it(): void
    {
        $user = $this->owner();
        [$target] = $this->targets(1);
        $origin = $this->web($user);
        $config = $target->sshConfig;
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $vault = app(SshTargetVault::class);
        $binding = app(TargetBatchBinding::class);
        $worker = app(TargetBatchWorker::class);
        $peer = SshTargetBinding::peerFingerprint($target, $config);
        $route = $target->transportAuthorityFingerprint();
        $grant = $credential->authorityFingerprint();
        $material = $credential->materialFingerprint();
        $dispatch = $credential->dispatchFingerprint();
        $original = $binding->hash($target);
        self::assertIsString($original);
        $history = $this->create($user, $origin, [$target]);
        $secret = $vault->open($target, $config, $credential);
        DB::transaction(function () use ($target, $credential, $vault, $config, $secret): void {
            Target::query()->whereKey($target->getKey())->lockForUpdate()->sole();
            $credential->forceFill(['encrypted_payload' => $vault->seal($target, $config, $secret['secret'], $secret['passphrase'])])->save();
        });
        self::assertSame($grant, $credential->authorityFingerprint());
        self::assertNotSame($material, $credential->materialFingerprint());
        self::assertNotSame($dispatch, $credential->dispatchFingerprint());
        self::assertSame($original, $binding->hash($target->fresh()));
        self::assertSame('completed', $worker->workOnce()['status']);
        $evidence = (array) DB::table('target_batch_items')->where('batch_id', $history)->sole();
        $old = $this->create($user, $origin, [$target->fresh()]);
        $material = $credential->materialFingerprint();
        $dispatch = $credential->dispatchFingerprint();
        DB::transaction(function () use ($target, $credential): void {
            Target::query()->whereKey($target->getKey())->lockForUpdate()->sole();
            $credential->supersedeAuthority();
        });
        $fresh = $target->fresh();
        self::assertSame($peer, SshTargetBinding::peerFingerprint($fresh, $fresh->sshConfig));
        self::assertSame($route, $fresh->transportAuthorityFingerprint());
        self::assertSame($material, $credential->materialFingerprint());
        self::assertNotSame($grant, $credential->authorityFingerprint());
        self::assertNotSame($dispatch, $credential->dispatchFingerprint());
        self::assertNotSame($original, $binding->hash($fresh));
        $blocked = $worker->workOnce();
        self::assertSame('blocked', $blocked['status']);
        self::assertSame('target_changed', $blocked['error_code']);
        self::assertSame('blocked', app(TargetBatchCoordinator::class)->status($user, $origin, $old)['items'][0]['status']);
        self::assertSame([$target->target_id], $this->fake->effects);
        $new = $this->create($user, $origin, [$fresh]);
        self::assertSame('completed', $worker->workOnce()['status']);
        self::assertSame('completed', app(TargetBatchCoordinator::class)->status($user, $origin, $new)['items'][0]['status']);
        self::assertSame($evidence, (array) DB::table('target_batch_items')->where('batch_id', $history)->sole());
    }

    public function test_reused_target_slug_never_revives_old_batch_authority(): void
    {
        $user = $this->owner();
        [$old] = $this->targets(1);
        $origin = $this->web($user);
        $oldBinding = app(TargetBatchBinding::class)->hash($old);
        $id = $this->create($user, $origin, [$old]);
        // Construct the already-recreated identity state directly; deletion
        // policy is tested separately. A journal must never use a public
        // slug to substitute another immutable Target record.
        $old->delete();
        [$replacement] = $this->targets(1);
        self::assertSame($old->target_id, $replacement->target_id);
        self::assertNotSame($old->getKey(), $replacement->getKey());
        self::assertNotSame($oldBinding, app(TargetBatchBinding::class)->hash($replacement));
        $worker = app(TargetBatchWorker::class);
        self::assertSame('blocked', $worker->workOnce()['status']);
        self::assertSame([], $this->fake->effects);
        self::assertSame('blocked', DB::table('target_batch_items')->where('batch_id', $id)->value('status'));
        $this->create($user, $origin, [$replacement]);
        self::assertSame('completed', $worker->workOnce()['status']);
        self::assertSame([$replacement->target_id], $this->fake->effects);
    }

    public function test_relay_disabled_interval_preview_and_queued_work_cannot_cross_restored_authority(): void
    {
        $user = $this->owner();
        $this->actingAs($user);
        [$target, $other] = $this->targets(2);
        $pin = $target->sshConfig->pinned_host_key;
        $relay = ConnectionRelay::query()->create([
            'relay_id' => 'batch-relay', 'display_name' => 'Fixture Relay',
            'control_host' => 'relay.example.test', 'control_port' => 22,
            'control_user' => 'deploy', 'control_host_key' => $pin,
            'local_socks_port' => 46081,
        ]);
        $url = '/admin/settings/connection-relays/'.$relay->getKey();
        $toggle = fn (int $revision, bool $enabled) => $this->post($url.'/toggle', [
            'relay_revision' => $revision, 'enable' => $enabled ? '1' : '0', 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasNoErrors();
        $toggle(1, true);
        $bindings = app(TargetTransportBinding::class);
        self::assertTrue($bindings->change($target, $bindings->revision($target), 'batch-relay'));
        $target->refresh();
        $epoch = $target->transport_revision;
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $cipher = $credential->encrypted_payload;
        $grant = $credential->authorityFingerprint();
        $peer = SshTargetBinding::peerFingerprint($target, $target->sshConfig);
        $route = $target->transportAuthorityFingerprint();
        $origin = $this->web($user);
        $core = app(TargetBatchCoordinator::class);
        $worker = app(TargetBatchWorker::class);
        $ids = [$target->target_id];
        $arguments = ['command' => 'uptime', 'timeout_seconds' => 10];
        $history = $this->create($user, $origin, [$target]);
        self::assertSame('completed', $worker->workOnce()['status']);
        $historicalRow = (array) DB::table('target_batch_items')->where('batch_id', $history)->sole();
        $old = $this->create($user, $origin, [$target]);
        $otherHash = app(TargetBatchBinding::class)->hash($other);

        $toggle(2, false);
        $disabled = $target->fresh();
        self::assertSame($epoch + 1, $disabled->transport_revision);
        try {
            app(ConnectionRelayRoutes::class)->sshRouteForTarget($disabled);
            self::fail('A disabled Relay must not dispatch.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('relay_unavailable', $e->reason);
        }
        $config = $disabled->sshConfig;
        $verification = app(SshVerificationState::class);
        $attempt = $verification->begin($disabled, $config, $credential);
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids, $arguments);
        $queued = $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run', $ids,
            $arguments, $preview['preview_token']);
        self::assertSame('queued', $queued['status']);
        $this->put($url, [
            'relay_id' => 'batch-relay', 'display_name' => 'Fixture Relay',
            'control_host' => 'replacement.example.test', 'control_port' => 2222,
            'control_user' => 'deploy', 'control_host_key' => $pin, 'local_socks_port' => 46082,
            'relay_revision' => 3, 'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasNoErrors();
        $toggle(4, true);
        $fresh = $target->fresh();
        self::assertSame($epoch + 2, $fresh->transport_revision);
        self::assertSame(46082, app(ConnectionRelayRoutes::class)->sshRouteForTarget($fresh)?->loopbackPort);
        $toggle(5, true);
        self::assertSame(5, $relay->fresh()->lifecycle_revision);
        self::assertSame($epoch + 2, $target->fresh()->transport_revision);
        self::assertSame($cipher, $credential->fresh()->encrypted_payload);
        self::assertSame($grant, $credential->fresh()->authorityFingerprint());
        self::assertSame($peer, SshTargetBinding::peerFingerprint($fresh, $fresh->sshConfig));
        self::assertNotSame($route, $fresh->transportAuthorityFingerprint());
        self::assertSame($otherHash, app(TargetBatchBinding::class)->hash($other->fresh()));
        $verification->failed($disabled, $config, $credential, $attempt, 'tcp_unreachable');
        try {
            $verification->succeeded($disabled, $config, $credential, $attempt, '127.0.0.1');
            self::fail('A disabled-interval Verify cannot become current after Enable.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('target_changed', $e->reason);
        }
        self::assertNull($target->fresh()->last_tested_at);
        try {
            $core->create($user, $origin, (string) Str::uuid(), 'ssh.command.run', $ids, $arguments, $preview['preview_token']);
            self::fail('An approval captured while disabled cannot authorize restored authority.');
        } catch (InvalidArgumentException $e) {
            self::assertStringContainsString('Preview again', $e->getMessage());
        }
        foreach ([$old, $queued['batch_id']] as $id) {
            self::assertSame('blocked', $worker->workOnce()['status']);
            self::assertSame('blocked', $core->status($user, $origin, $id)['items'][0]['status']);
        }
        self::assertSame([$target->target_id], $this->fake->effects);
        $new = $this->create($user, $origin, [$fresh]);
        self::assertSame('completed', $worker->workOnce()['status']);
        self::assertSame('completed', $core->status($user, $origin, $new)['items'][0]['status']);
        self::assertSame($historicalRow, (array) DB::table('target_batch_items')->where('batch_id', $history)->sole());
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

    public function test_lease_expiry_during_final_binding_lookup_cannot_admit_effect(): void
    {
        $user = $this->owner();
        $target = $this->targets(1)[0];
        $id = $this->create($user, $this->web($user), [$target]);
        $armed = false;
        $expired = false;
        $this->fake->onDispatch = static function () use (&$armed): void {
            $armed = true;
        };
        DB::listen(static function (QueryExecuted $query) use ($id, &$armed, &$expired): void {
            $sql = str_replace(['"', chr(96)], '', strtolower($query->sql));
            if ($armed && ! $expired && str_contains($sql, 'from target_credentials')
                && in_array('hashMany', array_column(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 'function'), true)) {
                $expired = true;
                DB::table('target_batch_items')->where('batch_id', $id)->update([
                    'lease_expires_at' => now()->subSecond(),
                ]);
            }
        });

        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertTrue($expired, 'Expire the lease after its initial read during final binding resolution.');
        self::assertSame([], $this->fake->effects);
        self::assertSame('blocked', $worked['status']);
        self::assertSame('dispatch_lease_expired', $worked['error_code']);
    }

    public function test_lease_is_checked_again_after_native_verification_inside_locked_admission(): void
    {
        $user = $this->owner();
        $id = $this->create($user, $this->web($user), $this->targets(1));
        $this->fake->duringAdmission = static function () use ($id): void {
            DB::table('target_batch_items')->where('batch_id', $id)->update([
                'lease_expires_at' => now()->subSecond(),
            ]);
        };
        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('blocked', $worked['status']);
        self::assertSame('dispatch_lease_expired', $worked['error_code']);
        self::assertSame([], $this->fake->effects);
        $child = DB::table('target_batch_items')->where('batch_id', $id)->sole();
        self::assertNotNull($child->effect_admitted);
        self::assertFalse((bool) $child->effect_admitted);
    }

    public function test_expired_never_admitted_claim_is_retired_without_unknown_or_replay(): void
    {
        $user = $this->owner();
        $origin = $this->web($user);
        $id = $this->create($user, $origin, $this->targets(1));
        $this->fake->onDispatch = static function () use ($id): void {
            DB::table('target_batch_items')->where('batch_id', $id)->update([
                'lease_expires_at' => now()->subSecond(),
            ]);
            self::assertNull(app(TargetBatchWorker::class)->workOnce());
        };
        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('blocked', $worked['status']);
        self::assertSame('dispatch_lease_expired', $worked['error_code']);
        self::assertSame([], $this->fake->effects);
        $child = DB::table('target_batch_items')->where('batch_id', $id)->sole();
        self::assertNotNull($child->effect_admitted);
        self::assertFalse((bool) $child->effect_admitted);
        self::assertNull($child->result_ciphertext);
        self::assertSame('failed', app(TargetBatchCoordinator::class)->status($user, $origin, $id)['status']);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
    }

    public function test_cancel_retires_never_admitted_claim_but_preserves_admitted_result(): void
    {
        $user = $this->owner();
        $origin = $this->web($user);
        $targets = $this->targets(2);
        $core = app(TargetBatchCoordinator::class);
        $before = $this->create($user, $origin, [$targets[0]]);
        $this->fake->onDispatch = static function () use ($core, $user, $origin, $before): void {
            self::assertSame('canceled', $core->cancel($user, $origin, $before)['status']);
        };
        self::assertSame('canceled', app(TargetBatchWorker::class)->workOnce()['status']);
        self::assertSame([], $this->fake->effects);
        $this->fake->onDispatch = null;

        $after = $this->create($user, $origin, [$targets[1]]);
        $this->fake->afterEffect = static function () use ($core, $user, $origin, $after): void {
            self::assertSame('cancel_requested', $core->cancel($user, $origin, $after)['status']);
        };
        self::assertSame('completed', app(TargetBatchWorker::class)->workOnce()['status']);
        self::assertSame([$targets[1]->target_id], $this->fake->effects);
        self::assertSame('completed', $core->status($user, $origin, $after)['status']);
    }

    public function test_claim_lease_respects_provider_declared_remote_budget_not_known_connector(): void
    {
        $this->fake->remoteSeconds = 195;
        config()->set('batch.lease_margin_seconds', 30);
        $user = $this->owner();
        $target = $this->targets(1)[0];
        $batchId = $this->create($user, $this->web($user), [$target]);
        $seconds = null;
        $this->fake->onDispatch = static function () use ($batchId, &$seconds): void {
            $item = DB::table('target_batch_items')->where('batch_id', $batchId)->firstOrFail();
            $seconds = Carbon::parse($item->started_at)
                ->diffInSeconds(Carbon::parse($item->lease_expires_at));
        };
        self::assertSame('completed', app(TargetBatchWorker::class)->workOnce()['status']);
        self::assertEqualsWithDelta(225, $seconds, 0.1);
    }

    public function test_newer_independent_batch_gets_a_turn_before_old_backlog_drains(): void
    {
        config()->set('batch.global_active', 1);
        config()->set('batch.user_active', 1);
        $user = $this->owner();
        $origin = $this->web($user);
        $targets = $this->targets(7);
        $older = $this->create($user, $origin, array_slice($targets, 0, 6));
        $newer = $this->create($user, $origin, [$targets[6]]);

        $worker = app(TargetBatchWorker::class);
        self::assertSame($targets[0]->target_id, $worker->workOnce()['target_id']);
        // An older long Batch remains runnable. Re-entering the worker from
        // scratch must rotate across eligible Batch parents, not favor the
        // oldest Batch until all six of its Targets have been exhausted.
        self::assertSame($targets[6]->target_id, $worker->workOnce()['target_id']);
        self::assertSame('completed', app(TargetBatchCoordinator::class)
            ->status($user, $origin, $newer)['status']);
        self::assertSame(1, DB::table('target_batch_items')->where('batch_id', $older)
            ->where('status', 'completed')->count());
        self::assertSame('running', DB::table('target_batches')->where('id', $older)->value('status'));
        self::assertCount(2, $this->fake->effects);
    }

    public function test_multiple_runnable_parents_rotate_even_on_tied_timestamps(): void
    {
        config()->set('batch.global_active', 1);
        config()->set('batch.user_active', 1);
        $user = $this->owner();
        $origin = $this->web($user);
        $targets = $this->targets(7);
        $older = $this->create($user, $origin, array_slice($targets, 0, 4));
        $middle = $this->create($user, $origin, array_slice($targets, 4, 2));
        $newer = $this->create($user, $origin, [$targets[6]]);

        // Timestamp ties must not change fair ordering; state is durable
        // across fresh worker instances without any process-local cursor.
        DB::table('target_batches')->whereIn('id', [$older, $middle, $newer])
            ->update(['created_at' => now()->startOfSecond()]);
        $actual = [];
        for ($i = 0; $i < 7; $i++) {
            $actual[] = app(TargetBatchWorker::class)->workOnce()['target_id'];
        }
        self::assertSame([
            $targets[0]->target_id, $targets[4]->target_id, $targets[6]->target_id,
            $targets[1]->target_id, $targets[5]->target_id,
            $targets[2]->target_id, $targets[3]->target_id,
        ], $actual);
        self::assertSame(7, (int) DB::table('operational_settings')->where('id', 1)
            ->value('batch_dispatch_turn'));
        self::assertSame(7, (int) DB::table('target_batches')->where('id', $older)
            ->value('last_dispatch_turn'));
        self::assertSame(5, (int) DB::table('target_batches')->where('id', $middle)
            ->value('last_dispatch_turn'));
        self::assertSame(3, (int) DB::table('target_batches')->where('id', $newer)
            ->value('last_dispatch_turn'));
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
    }

    public function test_busy_first_target_does_not_starve_other_targets_in_the_same_batch(): void
    {
        $user = $this->owner();
        $origin = $this->web($user);
        $targets = $this->targets(2);
        $core = app(TargetBatchCoordinator::class);
        $firstBatch = $this->create($user, $origin, [$targets[0]]);
        $ids = [$targets[0]->target_id, $targets[1]->target_id];
        $arguments = ['command' => 'uptime', 'timeout_seconds' => 10];
        $preview = $core->preview($user, $origin, 'ssh.command.run', $ids,
            $arguments, 'concurrent', false, 2);
        $secondBatch = $core->create($user, $origin, (string) Str::uuid(),
            'ssh.command.run', $ids, $arguments, $preview['preview_token'],
            'concurrent', false, 2)['batch_id'];

        $nested = null;
        $fake = $this->fake;
        $fake->onDispatch = static function () use (&$nested, $fake): void {
            // Batch A has made a durable claim but not completed its remote
            // effect. Another worker must progress Batch B's *free* child.
            $fake->onDispatch = null;
            $nested = app(TargetBatchWorker::class)->workOnce();
        };
        $outer = app(TargetBatchWorker::class)->workOnce();
        self::assertSame($targets[1]->target_id, $nested['target_id'] ?? null);
        self::assertSame('completed', $nested['status'] ?? null);
        self::assertSame($targets[0]->target_id, $outer['target_id']);
        self::assertSame('completed', $core->status($user, $origin, $firstBatch)['status']);

        $last = app(TargetBatchWorker::class)->workOnce();
        self::assertSame($targets[0]->target_id, $last['target_id']);
        self::assertSame('completed', $core->status($user, $origin, $secondBatch)['status']);
        self::assertCount(3, $fake->effects);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
    }

    public function test_rolling_batch_waits_for_busy_first_target_without_reordering(): void
    {
        $user = $this->owner();
        $origin = $this->web($user);
        $targets = $this->targets(2);
        $firstBatch = $this->create($user, $origin, [$targets[0]]);
        $orderedBatch = $this->create($user, $origin, $targets);
        $nested = 'not-called';
        $fake = $this->fake;
        $fake->onDispatch = static function () use (&$nested, $fake): void {
            $fake->onDispatch = null;
            $nested = app(TargetBatchWorker::class)->workOnce();
        };
        $outer = app(TargetBatchWorker::class)->workOnce();
        self::assertNull($nested, 'Rolling order cannot skip a temporarily busy first Target.');
        self::assertSame($targets[0]->target_id, $outer['target_id']);
        self::assertSame('completed', app(TargetBatchCoordinator::class)
            ->status($user, $origin, $firstBatch)['status']);
        self::assertSame($targets[0]->target_id, app(TargetBatchWorker::class)->workOnce()['target_id']);
        self::assertSame($targets[1]->target_id, app(TargetBatchWorker::class)->workOnce()['target_id']);
        self::assertSame('completed', app(TargetBatchCoordinator::class)
            ->status($user, $origin, $orderedBatch)['status']);
        self::assertSame([$targets[0]->target_id, $targets[0]->target_id, $targets[1]->target_id], $fake->effects);
    }

    public function test_worker_scans_beyond_one_bounded_page_of_in_flight_batches(): void
    {
        $user = $this->owner();
        $origin = $this->web($user);
        $targets = $this->targets(2);
        $busyBatchId = $this->create($user, $origin, [$targets[0]]);
        $source = (array) DB::table('target_batches')->where('id', $busyBatchId)->firstOrFail();
        $sourceItem = (array) DB::table('target_batch_items')->where('batch_id', $busyBatchId)->firstOrFail();
        $lease = now()->addHour();
        DB::table('target_batches')->where('id', $busyBatchId)->update(['status' => 'running']);
        DB::table('target_batch_items')->where('batch_id', $busyBatchId)->update([
            'status' => 'dispatching', 'lease_expires_at' => $lease,
            'dispatch_attempt_id' => (string) Str::uuid(),
        ]);
        // Synthetic, isolated already-claimed entries. No remote effect occurs.
        // Every one is still in-flight; the next eligible Batch must not be
        // hidden by the first 64 active entries or unbuffered PDO iteration.
        for ($i = 0; $i < 65; $i++) {
            $id = (string) Str::ulid();
            DB::table('target_batches')->insert([
                ...$source, 'id' => $id, 'request_id' => (string) Str::uuid(),
                'status' => 'running', 'created_at' => now()->subHour()->addSeconds($i),
            ]);
            DB::table('target_batch_items')->insert([
                ...$sourceItem, 'id' => (string) Str::ulid(), 'batch_id' => $id,
                'status' => 'dispatching', 'lease_expires_at' => $lease,
                'dispatch_attempt_id' => (string) Str::uuid(),
            ]);
        }
        config()->set('batch.global_active', 200);
        config()->set('batch.user_active', 200);
        $freeBatch = $this->create($user, $origin, [$targets[1]]);
        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertSame($targets[1]->target_id, $worked['target_id']);
        self::assertSame('completed', app(TargetBatchCoordinator::class)
            ->status($user, $origin, $freeBatch)['status']);
        self::assertSame([$targets[1]->target_id], $this->fake->effects);
        self::assertSame(66, DB::table('target_batch_items')->where('status', 'dispatching')->count());
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

    public function test_mixed_connector_binding_is_explicit_and_unimplemented_arvan_batch_cannot_dispatch(): void
    {
        $ssh = $this->targets(1)[0];
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'api.example.test' ? ['1.1.1.1'] : [];
            }
        });
        $arvan = app(TargetConnectorRegistry::class)->forType('arvancloud')->register([
            'target_id' => 'arvan-not-batch',
            'display_name' => 'Arvan future Batch fixture',
            'api_base_url' => 'https://api.example.test/cdn/4.0',
            'api_spec_url' => null, 'api_probe_path' => null,
            'api_key' => 'fixture-only-not-a-real-key',
        ]);
        $arvan->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $bindings = app(TargetBatchBinding::class)->hashMany([$ssh, $arvan]);
        self::assertIsString($bindings[$ssh->target_id]);
        self::assertNull($bindings[$arvan->target_id],
            'A connector without an audited optional Batch binding must never receive an invented proof.');
        self::assertSame($bindings[$ssh->target_id], app(TargetBatchBinding::class)->hash($ssh));
        self::assertNull(app(TargetBatchBinding::class)->hash($arvan));
        $owner = $this->owner();
        $plan = app(TargetBatchCoordinator::class)->preview($owner, $this->web($owner),
            'ssh.command.run', [$ssh->target_id, $arvan->target_id],
            ['command' => 'uptime', 'timeout_seconds' => 10]);
        self::assertSame(1, $plan['eligible_count']);
        self::assertSame('blocked', $plan['items'][1]['status']);
        self::assertNull($plan['items'][1]['target_record_id'],
            'A cross-connector request cannot disclose the unavailable Target binding.');
        self::assertSame([], $this->fake->effects);
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
