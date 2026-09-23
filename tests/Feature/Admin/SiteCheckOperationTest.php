<?php

namespace Tests\Feature\Admin;

use App\Application\Sites\SiteCheckOperationService;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteCheckOperation;
use App\Domain\Sites\SiteCheckOperationStatus;
use App\Domain\Sites\SiteCheckOperationTarget;
use App\Domain\Sites\SiteCheckTargetStatus;
use App\Domain\Sites\SiteConnectionState;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Tests\TestCase;

final class SiteCheckOperationTest extends TestCase
{
    use RefreshDatabase;

    /** @var list<string> */
    private array $checkedHosts = [];

    /** @var list<string> */
    private array $failingHosts = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(function (Request $request) {
            $host = (string) parse_url($request->url(), PHP_URL_HOST);
            $base = 'https://'.$host;
            $path = (string) parse_url($request->url(), PHP_URL_PATH);

            if ($path === '/.well-known/oauth-protected-resource') {
                $this->checkedHosts[] = $host;

                if (in_array($host, $this->failingHosts, true)) {
                    return Http::response([], 404);
                }

                return Http::response([
                    'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                    'authorization_servers' => [$base],
                    'scopes_supported' => ['mcp:use', 'offline_access'],
                    'bearer_methods_supported' => ['header'],
                    'resource_name' => 'WP AI Bridge',
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

            return Http::response([], 404);
        });
    }

    public function test_bulk_check_is_durable_idempotent_and_only_advances_on_post(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $key = (string) Str::uuid();

        $response = $this->actingAs($user)->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $beta->site_id],
            'idempotency_key' => $key,
        ]);

        $operation = SiteCheckOperation::query()->sole();
        $response->assertRedirect(route('admin.site-checks.show', ['operation' => $operation->getKey()], false));
        self::assertSame(SiteCheckOperationStatus::Pending, $operation->statusValue());
        self::assertSame(1, $operation->active_slot);
        self::assertSame(2, $operation->targets()->count());
        self::assertSame([], $this->checkedHosts);

        $this->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $beta->site_id],
            'idempotency_key' => $key,
        ])->assertRedirect(route('admin.site-checks.show', ['operation' => $operation->getKey()], false));

        self::assertSame(1, SiteCheckOperation::query()->count());
        self::assertSame(2, SiteCheckOperationTarget::query()->count());
        self::assertSame([], $this->checkedHosts);

        $gamma = $this->site('gamma');
        $this->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $gamma->site_id],
            'idempotency_key' => $key,
        ])->assertSessionHasErrors('bulk_check');

        self::assertSame(1, SiteCheckOperation::query()->count());
        self::assertSame(2, SiteCheckOperationTarget::query()->count());
        self::assertSame([], $this->checkedHosts);

        $this->get(route('admin.site-checks.show', ['operation' => $operation->getKey()], false))
            ->assertOk()
            ->assertSee('Alpha')
            ->assertSee('Beta');
        self::assertSame([], $this->checkedHosts);

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false))
            ->assertRedirect(route('admin.site-checks.show', ['operation' => $operation->getKey()], false));

        self::assertSame(['alpha.example.test'], $this->checkedHosts);
        $targets = $operation->targets()->orderBy('position')->get();
        self::assertSame(SiteCheckTargetStatus::Succeeded, $targets[0]->statusValue());
        self::assertSame(1, $targets[0]->attempts);
        self::assertSame(SiteCheckTargetStatus::Pending, $targets[1]->statusValue());

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));
        self::assertSame(['alpha.example.test', 'beta.example.test'], $this->checkedHosts);

        $operation->refresh();
        self::assertSame(SiteCheckOperationStatus::Completed, $operation->statusValue());
        self::assertNull($operation->active_slot);
        self::assertNotNull($operation->completed_at);
        self::assertSame(2, DB::table('activity_events')
            ->where('correlation_id', $operation->getKey())
            ->where('operation', 'bulk-site-connection-test')
            ->where('outcome', 'success')
            ->count());

        $this->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $beta->site_id],
            'idempotency_key' => $key,
        ])->assertRedirect(route('admin.site-checks.show', ['operation' => $operation->getKey()], false));

        self::assertSame(1, SiteCheckOperation::query()->count());
        self::assertSame(['alpha.example.test', 'beta.example.test'], $this->checkedHosts);
    }

    public function test_target_selection_is_atomic_authorized_and_bounded(): void
    {
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $gamma = $this->site('gamma');
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $this->grantSite($operator, $alpha);
        $this->grantSite($operator, $beta);

        $this->actingAs($operator)->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $gamma->site_id],
            'idempotency_key' => (string) Str::uuid(),
        ])->assertSessionHasErrors('bulk_check');

        self::assertSame(0, SiteCheckOperation::query()->count());
        self::assertSame([], $this->checkedHosts);

        $this->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id],
            'idempotency_key' => (string) Str::uuid(),
        ])->assertSessionHasErrors('site_ids');

        $this->post(route('admin.site-checks.store', [], false), [
            'site_ids' => array_map(static fn (int $n): string => 'site-'.$n, range(1, 51)),
            'idempotency_key' => (string) Str::uuid(),
        ])->assertSessionHasErrors('site_ids');

        self::assertSame(0, SiteCheckOperation::query()->count());
        self::assertSame([], $this->checkedHosts);
    }

    public function test_fifty_targets_are_created_with_bounded_queries_and_no_remote_fanout(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $siteIds = [];

        for ($index = 1; $index <= SiteCheckOperationService::MAX_TARGETS; $index++) {
            $siteIds[] = $this->site(sprintf('site-%02d', $index))->site_id;
        }

        DB::flushQueryLog();
        DB::enableQueryLog();

        $operation = app(SiteCheckOperationService::class)->start(
            $user,
            $siteIds,
            (string) Str::uuid(),
        );

        $queryCount = count(DB::getQueryLog());
        DB::disableQueryLog();

        self::assertSame(SiteCheckOperationService::MAX_TARGETS, $operation->targets()->count());
        self::assertLessThanOrEqual(12, $queryCount);
        self::assertSame([], $this->checkedHosts);
    }

    public function test_permission_revocation_blocks_only_that_target_and_redacts_its_identity(): void
    {
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $operator = $this->user(GatewayRole::Operator, SiteScopeMode::Selected);
        $this->grantSite($operator, $alpha);
        $this->grantSite($operator, $beta);

        $this->actingAs($operator)->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $beta->site_id],
            'idempotency_key' => (string) Str::uuid(),
        ]);

        $operation = SiteCheckOperation::query()->sole();
        DB::table('user_site_permission_denials')->insert([
            'user_id' => $operator->getKey(),
            'site_record_id' => $alpha->getKey(),
            'permission' => GatewayPermission::ConnectionsTest->value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->get(route('admin.site-checks.show', ['operation' => $operation->getKey()], false))
            ->assertOk()
            ->assertSee('Access unavailable')
            ->assertDontSee('Alpha')
            ->assertSee('Beta');

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));
        $first = $operation->targets()->where('position', 1)->firstOrFail();
        self::assertSame(SiteCheckTargetStatus::AuthorizationBlocked, $first->statusValue());
        self::assertSame(0, $first->attempts);
        self::assertSame('authorization_revoked', $first->error_code);
        self::assertSame([], $this->checkedHosts);

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));
        self::assertSame(['beta.example.test'], $this->checkedHosts);
        self::assertSame(
            SiteCheckOperationStatus::Completed,
            $operation->refresh()->statusValue(),
        );
    }

    public function test_partial_failure_is_visible_and_explicit_retry_is_capped(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $this->failingHosts = ['beta.example.test'];

        $this->actingAs($user)->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $beta->site_id],
            'idempotency_key' => (string) Str::uuid(),
        ]);
        $operation = SiteCheckOperation::query()->sole();

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));
        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));

        $betaTarget = $operation->targets()->where('position', 2)->firstOrFail();
        self::assertSame(SiteCheckTargetStatus::Failed, $betaTarget->statusValue());
        self::assertSame(1, $betaTarget->attempts);
        self::assertNotNull($betaTarget->error_code);
        self::assertSame(SiteCheckOperationStatus::Completed, $operation->refresh()->statusValue());

        for ($attempt = 2; $attempt <= SiteCheckOperationService::MAX_ATTEMPTS; $attempt++) {
            $this->post(route('admin.site-checks.retry', [
                'operation' => $operation->getKey(),
                'target' => $betaTarget->getKey(),
            ], false))->assertRedirect();

            self::assertSame(SiteCheckTargetStatus::Pending, $betaTarget->refresh()->statusValue());

            $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));
            self::assertSame(SiteCheckTargetStatus::Failed, $betaTarget->refresh()->statusValue());
            self::assertSame($attempt, $betaTarget->attempts);
        }

        $this->post(route('admin.site-checks.retry', [
            'operation' => $operation->getKey(),
            'target' => $betaTarget->getKey(),
        ], false))->assertSessionHasErrors('bulk_check');

        self::assertSame(SiteCheckTargetStatus::Failed, $betaTarget->refresh()->statusValue());
        self::assertSame(SiteCheckOperationService::MAX_ATTEMPTS, $betaTarget->attempts);
        self::assertSame(
            1 + SiteCheckOperationService::MAX_ATTEMPTS,
            count($this->checkedHosts),
        );
    }

    public function test_stale_running_target_becomes_interrupted_then_can_be_retried_without_silent_reexecution(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $operation = app(SiteCheckOperationService::class)->start(
            $user,
            [$alpha->site_id, $beta->site_id],
            (string) Str::uuid(),
        );
        $alphaTarget = $operation->targets()->where('position', 1)->firstOrFail();
        $alphaTarget->forceFill([
            'status' => SiteCheckTargetStatus::Running,
            'attempts' => 1,
            'attempt_token' => (string) Str::uuid(),
            'started_at' => now()->subMinutes(10),
        ])->save();
        $operation->forceFill([
            'status' => SiteCheckOperationStatus::Running,
            'started_at' => now()->subMinutes(10),
        ])->save();

        app(SiteCheckOperationService::class)->advance($user, $operation);

        self::assertSame(SiteCheckTargetStatus::Interrupted, $alphaTarget->refresh()->statusValue());
        self::assertSame(1, $alphaTarget->attempts);
        self::assertSame('request_interrupted', $alphaTarget->error_code);
        self::assertSame(['beta.example.test'], $this->checkedHosts);
        self::assertSame(SiteCheckOperationStatus::Completed, $operation->refresh()->statusValue());

        $this->actingAs($user)->post(route('admin.site-checks.retry', [
            'operation' => $operation->getKey(),
            'target' => $alphaTarget->getKey(),
        ], false))->assertRedirect();

        self::assertSame(SiteCheckTargetStatus::Pending, $alphaTarget->refresh()->statusValue());

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false));

        self::assertSame(SiteCheckTargetStatus::Succeeded, $alphaTarget->refresh()->statusValue());
        self::assertSame(2, $alphaTarget->attempts);
        self::assertSame(['beta.example.test', 'alpha.example.test'], $this->checkedHosts);
    }

    public function test_deleted_target_is_terminal_and_completed_state_is_pruned_after_retention(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $operation = app(SiteCheckOperationService::class)->start(
            $user,
            [$alpha->site_id, $beta->site_id],
            (string) Str::uuid(),
        );

        $alpha->delete();
        app(SiteCheckOperationService::class)->advance($user, $operation);
        $missing = $operation->targets()->where('position', 1)->firstOrFail();
        self::assertSame(SiteCheckTargetStatus::Missing, $missing->statusValue());
        self::assertSame(0, $missing->attempts);
        self::assertSame([], $this->checkedHosts);

        app(SiteCheckOperationService::class)->advance($user, $operation);
        self::assertSame(['beta.example.test'], $this->checkedHosts);

        $operation->refresh()->forceFill([
            'completed_at' => now()->subDays(SiteCheckOperationService::RETENTION_DAYS + 1),
            'active_slot' => null,
            'status' => SiteCheckOperationStatus::Completed,
        ])->save();

        $gamma = $this->site('gamma');
        $delta = $this->site('delta');
        $replacement = app(SiteCheckOperationService::class)->start(
            $user,
            [$gamma->site_id, $delta->site_id],
            (string) Str::uuid(),
        );

        self::assertNull(SiteCheckOperation::query()->find($operation->getKey()));
        self::assertNotNull(SiteCheckOperation::query()->find($replacement->getKey()));
    }

    public function test_new_operation_redirects_to_existing_active_operation_and_other_users_cannot_view_it(): void
    {
        $owner = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $other = $this->user(GatewayRole::Administrator, SiteScopeMode::All, 'other@example.test');
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');
        $gamma = $this->site('gamma');
        $delta = $this->site('delta');

        $this->actingAs($owner)->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$alpha->site_id, $beta->site_id],
            'idempotency_key' => (string) Str::uuid(),
        ]);
        $operation = SiteCheckOperation::query()->sole();

        $this->post(route('admin.site-checks.store', [], false), [
            'site_ids' => [$gamma->site_id, $delta->site_id],
            'idempotency_key' => (string) Str::uuid(),
        ])->assertRedirect(route('admin.site-checks.show', ['operation' => $operation->getKey()], false));

        self::assertSame(1, SiteCheckOperation::query()->count());

        $this->actingAs($other)
            ->get(route('admin.site-checks.show', ['operation' => $operation->getKey()], false))
            ->assertNotFound();

        $this->post(route('admin.site-checks.advance', ['operation' => $operation->getKey()], false))
            ->assertNotFound();

        self::assertSame([], $this->checkedHosts);
    }

    public function test_disabled_creator_blocks_remote_execution_without_consuming_an_attempt(): void
    {
        $user = $this->user(GatewayRole::Administrator, SiteScopeMode::All);
        $alpha = $this->site('alpha');
        $beta = $this->site('beta');

        $operation = app(SiteCheckOperationService::class)->start(
            $user,
            [$alpha->site_id, $beta->site_id],
            (string) Str::uuid(),
        );

        $user->forceFill(['access_enabled' => false])->save();

        app(SiteCheckOperationService::class)->advance($user, $operation);

        $first = $operation->targets()->where('position', 1)->firstOrFail();
        self::assertSame(SiteCheckTargetStatus::AuthorizationBlocked, $first->statusValue());
        self::assertSame(0, $first->attempts);
        self::assertSame('creator_unavailable', $first->error_code);
        self::assertSame([], $this->checkedHosts);
    }

    public function test_bulk_check_routes_stay_inside_authenticated_web_boundary(): void
    {
        foreach ([
            'admin.site-checks.store',
            'admin.site-checks.show',
            'admin.site-checks.advance',
            'admin.site-checks.retry',
        ] as $name) {
            $route = Route::getRoutes()->getByName($name);
            self::assertNotNull($route, $name);
            self::assertContains('web', $route->middleware(), $name);
            self::assertContains('auth', $route->middleware(), $name);
            self::assertContains(
                \App\Http\Middleware\EnsureLocalUserAccessEnabled::class,
                $route->middleware(),
                $name,
            );
        }

        $this->get('/admin/site-checks/'.Str::uuid())->assertRedirect('/admin/login');
    }

    private function user(
        GatewayRole $role,
        SiteScopeMode $scope,
        string $email = 'operator@example.test',
    ): User {
        return User::query()->create([
            'name' => 'Bulk Check Operator',
            'email' => $email,
            'password' => 'CorrectHorse!234',
            'role' => $role->value,
            'site_scope_mode' => $scope->value,
            'access_enabled' => true,
        ]);
    }

    private function site(string $siteId): Site
    {
        $base = 'https://'.$siteId.'.example.test';

        return Site::query()->create([
            'site_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => SiteConnectionState::Disconnected,
        ]);
    }

    private function grantSite(User $user, Site $site): void
    {
        DB::table('user_site_access')->insert([
            'user_id' => $user->getKey(),
            'site_record_id' => $site->getKey(),
            'allowed' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
