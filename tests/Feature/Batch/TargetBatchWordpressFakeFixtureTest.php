<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchBinding;
use App\Application\Batch\TargetBatchCoordinator;
use App\Application\Batch\TargetBatchWorker;
use App\Application\Batch\WordpressBridgeInfoBatchProvider;
use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request as HttpRequest;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

/** Connector-neutral Batch proof against a fake WordPress MCP transport. */
final class TargetBatchWordpressFakeFixtureTest extends TestCase
{
    use RefreshDatabase;

    /** @var list<string> */
    private array $abilityCalls = [];

    private bool $rejectBridgeInfo = false;

    protected function setUp(): void
    {
        parent::setUp();
        config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
        config()->set('bridge.client.name', 'Gateway V3 Test');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });
        Http::preventStrayRequests();
        Http::fake(fn ($request) => $this->respond($request));
    }

    public function test_wordpress_batch_lease_covers_full_native_mcp_sequence_and_refresh_recovery(): void
    {
        $provider = app(WordpressBridgeInfoBatchProvider::class);
        config()->set('bridge.http.request_timeout_seconds', 5);
        self::assertSame(70, $provider->remoteTimeoutSeconds([]));
        config()->set('bridge.http.request_timeout_seconds', 30);
        self::assertSame(195, $provider->remoteTimeoutSeconds([]));

        // The remote phase budget must include four sequential MCP calls,
        // the possible refresh request, and the 45s one-shot recovery window;
        // crash reconciliation adds a separate configured lease margin.
        config()->set('batch.lease_margin_seconds', 30);
        self::assertSame(225, $provider->remoteTimeoutSeconds([])
            + max(30, (int) config('batch.lease_margin_seconds')));
    }

    public function test_readonly_wordpress_bridge_provider_uses_same_durable_batch_core_without_publishing(): void
    {
        $user = User::query()->create([
            'name' => 'WP Batch User', 'email' => 'wp-v3-batch@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $ids = [];
        foreach (['wp-batch-a', 'wp-batch-b'] as $name) {
            $target = app(WpAiBridgeTargetRegistration::class)->register(
                $name, 'WP '.$name, 'https://'.$name.'.example.test',
            );
            $connection = app(WpAiBridgeTargetConnectionService::class);
            $url = $connection->begin($target);
            parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
            $connection->completeCallback((string) $query['state'], $name.'-code',
                'https://'.$name.'.example.test', null);
            $ids[] = $name;
        }
        // Legitimate OAuth refresh rotates the encrypted access/refresh token
        // and credential generation, but must NOT invalidate a durable read
        // already bound to the same consent identity and Target. A genuine
        // consent/client binding change still invalidates the preview.
        $wp = Target::query()->where('target_id', $ids[0])->firstOrFail();
        $identity = app(TargetBatchBinding::class);
        $beforeRotation = $identity->hash($wp);
        self::assertIsString($beforeRotation);
        $credential = DB::table('target_credentials')->where('target_record_id', $wp->getKey())->first();
        self::assertNotNull($credential);
        DB::table('target_credentials')->where('id', $credential->id)->update([
            'encrypted_payload' => Crypt::encryptString('synthetic-rotated-token-not-used'),
        ]);
        DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->id)
            ->increment('generation');
        self::assertSame($beforeRotation, $identity->hash($wp));
        DB::table('target_credentials')->where('id', $credential->id)->update([
            'encrypted_payload' => $credential->encrypted_payload,
        ]);
        DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->id)
            ->update(['binding_hash' => hash('sha256', 'synthetic-new-client-consent')]);
        self::assertNotSame($beforeRotation, $identity->hash($wp));
        DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->id)
            ->update(['binding_hash' => hash('sha256', (string) $wp->getKey()."\0".$wp->target_id."\0".
                (string) config('bridge.client.id')."\0".
                'https://'.$ids[0].'.example.test/wp-json/wp-ai-bridge/v1/mcp')]);
        self::assertSame($beforeRotation, $identity->hash($wp));

        $request = HttpRequest::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $preview = $core->preview($user, $origin, 'wordpress.bridge.info', $ids, [],
            'rolling', true, 1);
        self::assertFalse($preview['effectful']);
        self::assertSame(2, $preview['eligible_count']);
        $created = $core->create($user, $origin, (string) Str::uuid(),
            'wordpress.bridge.info', $ids, [], $preview['preview_token'], 'rolling', true, 1);
        // The full native sequence can consume multiple HTTP deadlines; the
        // durable claimed lease must cover all of them before the first call.
        config()->set('bridge.http.request_timeout_seconds', 30);
        config()->set('batch.lease_margin_seconds', 30);
        $worker = app(TargetBatchWorker::class);
        foreach ($ids as $name) {
            $outcome = $worker->workOnce();
            self::assertSame($name, $outcome['target_id']);
            self::assertSame('completed', $outcome['status'], json_encode($outcome, JSON_THROW_ON_ERROR));
        }
        $leases = DB::table('target_batch_items')->where('batch_id', $created['batch_id'])
            ->orderBy('position')->get(['started_at', 'lease_expires_at']);
        self::assertCount(2, $leases);
        foreach ($leases as $lease) {
            self::assertSame(225,
                Carbon::parse($lease->lease_expires_at)->getTimestamp()
                    - Carbon::parse($lease->started_at)->getTimestamp());
        }
        $status = $core->status($user, $origin, $created['batch_id']);
        self::assertSame('completed', $status['status']);
        self::assertSame(2, $status['counts']['completed']);
        foreach ($status['items'] as $item) {
            self::assertSame('wp-ai-bridge/bridge-info', $item['result']['result']['ability']);
        }
        self::assertSame([
            'wp-ai-bridge/abilities-read', 'wp-ai-bridge/bridge-info',
            'wp-ai-bridge/abilities-read', 'wp-ai-bridge/bridge-info',
        ], $this->abilityCalls);
        self::assertNull($worker->workOnce());
    }

    public function test_committed_disconnect_fences_queued_authority_even_when_remote_revocation_fails(): void
    {
        $user = User::query()->create([
            'name' => 'WP Batch Owner', 'email' => 'wp-batch-revoke@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $target = app(WpAiBridgeTargetRegistration::class)->register(
            'wp-batch-revoke', 'WP Revoke', 'https://wp-batch-revoke.example.test',
        );
        $connection = app(WpAiBridgeTargetConnectionService::class);
        parse_str((string) parse_url($connection->begin($target), PHP_URL_QUERY), $query);
        $connection->completeCallback((string) $query['state'], 'wp-code', 'https://wp-batch-revoke.example.test', null);
        $target->refresh();
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $material = $credential->materialFingerprint();
        $grant = $credential->authorityFingerprint();
        $request = HttpRequest::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $preview = $core->preview($user, $origin, 'wordpress.bridge.info', [$target->target_id], []);
        self::assertSame(1, $preview['eligible_count']);
        $created = $core->create($user, $origin, (string) Str::uuid(),
            'wordpress.bridge.info', [$target->target_id], [], $preview['preview_token']);
        // The fixture rejects the revocation endpoint, so the real service
        // commits the local intent but cannot claim successful remote revoke.
        try {
            $connection->disconnect($target);
            self::fail('Revocation must not claim remote confirmation.');
        } catch (WpAiBridgeTargetConnectionException $exception) {
            self::assertSame('revocation_failed', $exception->reason);
        }
        self::assertSame($material, $credential->fresh()->materialFingerprint());
        self::assertNotSame($grant, $credential->fresh()->authorityFingerprint());
        self::assertSame(1, $credential->fresh()->authority_revision);
        self::assertNotNull(DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $target->getKey())->first());
        self::assertNull(app(TargetBatchBinding::class)->hash($target->fresh()));
        // Even the pre-disconnect connected model cannot supply a grant
        // after the durable intent was created.
        self::assertNull(app(TargetBatchBinding::class)->hash($target));
        $outcome = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('blocked', $outcome['status']);
        self::assertSame('authorization_revoked', $outcome['error_code']);
        self::assertSame([], $this->abilityCalls);
        self::assertSame('blocked', $core->status($user, $origin, $created['batch_id'])['items'][0]['status']);
    }

    public function test_failed_wordpress_provider_preserves_native_cause_and_original_reference_in_batch_activity(): void
    {
        $user = User::query()->create([
            'name' => 'WP Batch Failure User', 'email' => 'wp-batch-failure@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $target = app(WpAiBridgeTargetRegistration::class)->register(
            'wp-batch-failure', 'WP Failure', 'https://wp-batch-failure.example.test',
        );
        $connection = app(WpAiBridgeTargetConnectionService::class);
        $url = $connection->begin($target);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $connection->completeCallback((string) $query['state'], 'wp-batch-failure-code',
            'https://wp-batch-failure.example.test', null);
        $this->rejectBridgeInfo = true;

        $request = HttpRequest::create('/admin/target-batches', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($user, $request);
        $core = app(TargetBatchCoordinator::class);
        $preview = $core->preview($user, $origin, 'wordpress.bridge.info',
            [$target->target_id], []);
        $created = $core->create($user, $origin, (string) Str::uuid(),
            'wordpress.bridge.info', [$target->target_id], [], $preview['preview_token']);
        $worked = app(TargetBatchWorker::class)->workOnce();
        self::assertSame('failed', $worked['status']);
        self::assertSame('downstream_rejected', $worked['error_code']);
        $activity = DB::table('activity_events')
            ->where('correlation_id', $worked['diagnostic_reference'])->first();
        self::assertNotNull($activity);
        $context = json_decode((string) $activity->diagnostic_context, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame($created['batch_id'], $context['batch_id']);
        self::assertTrue(Str::isUuid($context['downstream_diagnostic_reference']));
        self::assertSame('downstream_rejected', $context['provider_error_code']);
        self::assertSame('wp_permission_denied', $context['source_error_code']);
        self::assertSame('Role lacks permission', $context['source_error_message']);
        self::assertSame('missing_role', $context['source_error_details']['reason']);
        $native = DB::table('activity_events')
            ->where('correlation_id', $context['downstream_diagnostic_reference'])
            ->where('target_record_id', $target->getKey())->first();
        self::assertNotNull($native);
        self::assertSame('downstream_rejected', $native->error_code);
        self::assertSame('failed', $core->status($user, $origin, $created['batch_id'])['status']);
        self::assertSame(['wp-ai-bridge/abilities-read', 'wp-ai-bridge/bridge-info'], $this->abilityCalls);
        self::assertNull(app(TargetBatchWorker::class)->workOnce());
    }

    private function respond($request)
    {
        $host = (string) parse_url($request->url(), PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
            ], 200);
        }
        if ($path === '/.well-known/oauth-authorization-server') {
            return Http::response([
                'issuer' => $base,
                'authorization_endpoint' => $base.'/wp-ai-bridge/oauth/authorize',
                'token_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
                'revocation_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'scopes_supported' => ['mcp:use', 'offline_access'],
            ], 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/token') {
            return Http::response([
                'token_type' => 'Bearer', 'expires_in' => 3600,
                'access_token' => $host.'-access', 'refresh_token' => $host.'-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/mcp' && $request->method() === 'POST') {
            $data = $request->data();
            if (($data['method'] ?? null) === 'initialize') {
                return Http::response(['jsonrpc' => '2.0', 'id' => 1,
                    'result' => ['protocolVersion' => '2025-11-25', 'capabilities' => (object) []],
                ], 200, ['Mcp-Session-Id' => 'batch-test-session']);
            }
            if (($data['method'] ?? null) === 'tools/call') {
                $ability = (string) ($data['params']['arguments']['ability_name'] ?? '');
                $this->abilityCalls[] = $ability;
                if ($this->rejectBridgeInfo && $ability === 'wp-ai-bridge/bridge-info') {
                    return Http::response([
                        'jsonrpc' => '2.0', 'id' => $data['id'] ?? 2,
                        'result' => [
                            'isError' => true,
                            'content' => [['type' => 'text', 'text' => 'Role lacks permission']],
                            'structuredContent' => [
                                'error' => [
                                    'code' => 'wp_permission_denied',
                                    'message' => 'Role lacks permission',
                                    'data' => ['reason' => 'missing_role'],
                                ],
                            ],
                        ],
                    ], 200);
                }
                if (! in_array($ability, ['wp-ai-bridge/abilities-read', 'wp-ai-bridge/bridge-info'], true)) {
                    return Http::response(['error' => 'Mutating WordPress ability forbidden by fixture'], 403);
                }
                $result = $ability === 'wp-ai-bridge/abilities-read'
                    ? ['items' => [['name' => 'wp-ai-bridge/bridge-info', 'mcp_type' => 'tool',
                        'bridge_delegation' => 'ability_specific',
                        'annotations' => ['readonly' => true, 'destructive' => false]]]]
                    : ['host' => $host, 'ability' => $ability];

                return Http::response(['jsonrpc' => '2.0', 'id' => $data['id'] ?? 2,
                    'result' => ['isError' => false,
                        'structuredContent' => ['success' => true, 'data' => $result]],
                ], 200);
            }
        }
        if ($path === '/wp-json/wp-ai-bridge/v1/mcp' && $request->method() === 'DELETE') {
            return Http::response('', 200);
        }

        return Http::response(['error' => 'unsupported mocked request'], 404);
    }
}
