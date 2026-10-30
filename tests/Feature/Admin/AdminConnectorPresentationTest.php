<?php

namespace Tests\Feature\Admin;

use App\Application\Admin\TargetConnectorAdmin;
use App\Application\Admin\TargetConnectorAdminDefinition;
use App\Application\Admin\TargetConnectorAdminPresenter;
use App\Application\Targets\TargetConnectorRegistry;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ViewErrorBag;
use Tests\TestCase;

final class AdminConnectorPresentationTest extends TestCase
{
    use RefreshDatabase;

    public function test_enrollment_options_require_runtime_support_and_reviewed_local_views(): void
    {
        $admin = app(TargetConnectorAdmin::class);
        self::assertSame(app(TargetConnectorRegistry::class)->types(), array_keys($admin->options()));
        self::assertNull($admin->forType('unrecognized_connector'));
        self::assertSame('Unsupported connector', $admin->label('unrecognized_connector'));
        self::assertArrayNotHasKey('ai_server_agent', $admin->options());

        foreach (array_keys($admin->options()) as $type) {
            $presenter = $admin->forType($type);
            self::assertNotNull($presenter);
            $definition = $presenter->definition();
            self::assertSame($type, $definition->type);
            foreach (get_object_vars($definition) as $key => $value) {
                if (str_ends_with($key, 'View') && $value !== null) {
                    self::assertStringStartsWith('admin.targets.connectors.', $value);
                    self::assertTrue(view()->exists($value), $value);
                }
            }
        }

        $this->actingAs($this->owner())->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()->assertSee('Trusted OpenSSH server public host key')
            ->assertSee('name="ssh_password"', false)->assertSee('name="_token"', false);
    }

    public function test_unsupported_stored_connector_has_neutral_evidence_and_no_invented_ssh_or_oauth_recovery(): void
    {
        $target = $this->target('historical', 'wp_ai_bridge');
        DB::table('targets')->where('id', $target->getKey())->update(['connector_type' => 'historical_protocol']);
        Http::preventStrayRequests();

        $this->actingAs($this->owner())->get('/admin/targets/historical')->assertOk()
            ->assertSee('Unsupported connector')->assertSee('Connector unavailable')
            ->assertSee('Its authentication, reachability and recovery requirements have not been evaluated.')
            ->assertDontSee('SSH connection last verified')->assertDontSee('SSH connection needs attention')
            ->assertDontSee('WordPress authorization required')
            ->assertDontSee('action="'.route('admin.targets.connect', ['target' => 'historical']).'"', false);
        $this->get('/admin/targets/historical/edit')->assertOk()
            ->assertDontSee('name="configuration_revision"', false);
        $this->get('/admin/targets')->assertOk()->assertSee('Connector unavailable');
        Http::assertNothingSent();
    }

    public function test_inventory_enrichment_is_batched_and_limited_to_the_authorized_page(): void
    {
        Http::preventStrayRequests();
        $owner = $this->owner();
        $this->target('wp-001', 'wp_ai_bridge');
        $one = app(TargetInventory::class)->adminPage($owner)['items'];
        [$single, $singleQueries] = $this->presentWithQueries($one);
        self::assertCount(1, $single);
        self::assertLessThanOrEqual(4, count($singleQueries));

        for ($i = 2; $i <= 55; $i++) {
            $this->target(sprintf('wp-%03d', $i), 'wp_ai_bridge');
        }
        $page = app(TargetInventory::class)->adminPage($owner)['items'];
        [$many, $manyQueries] = $this->presentWithQueries($page);
        self::assertCount(50, $many);
        self::assertCount(count($singleQueries), $manyQueries);
        self::assertArrayNotHasKey('wp-055', $many);
        $pageIds = array_map(static fn (Target $target): string => (string) $target->getKey(), $page);
        foreach ($manyQueries as $query) {
            foreach ($query['bindings'] as $binding) {
                if (is_string($binding) && strlen($binding) === 26) {
                    self::assertContains($binding, $pageIds);
                }
            }
        }
        Http::assertNothingSent();
    }

    public function test_ssh_inventory_does_not_lazy_load_configuration_when_no_projection_is_supplied(): void
    {
        $target = $this->target('ssh-no-projection', 'ssh_direct');
        self::assertFalse($target->relationLoaded('sshConfig'));
        [$rows, $queries] = $this->presentWithQueries([$target]);
        self::assertSame([], $queries);
        self::assertNull($rows['ssh-no-projection']['identity']);
        self::assertSame('Direct SSH', $rows['ssh-no-projection']['label']);
    }

    public function test_a_third_synthetic_presentation_renders_the_shared_page_without_registering_a_connector(): void
    {
        $presenter = new class implements TargetConnectorAdminPresenter
        {
            public function definition(): TargetConnectorAdminDefinition
            {
                return new TargetConnectorAdminDefinition(type: 'synthetic_protocol', label: 'Synthetic <service>');
            }

            public function inventory(array $targets): array
            {
                return [];
            }

            public function recovery(Target $target, array $details): array
            {
                return [
                    'title' => 'Synthetic verification evidence',
                    'description' => 'Synthetic operator guidance',
                    'reachability' => 'Not checked', 'authorization' => 'Unknown',
                    'operation' => 'No pending operation', 'history' => null, 'tone' => 'neutral',
                ];
            }

            public function hasConfiguration(array $details): bool
            {
                return false;
            }
        };
        $target = new Target([
            'target_id' => 'synthetic', 'display_name' => 'Synthetic Target',
            'connector_type' => 'synthetic_protocol', 'connection_state' => TargetConnectionState::Disconnected,
        ]);
        $this->actingAs($this->owner());
        $html = view('admin.targets.show', [
            'target' => $target, 'connectorUi' => $presenter->definition(),
            'recovery' => $presenter->recovery($target, []), 'canRemoveSafely' => true,
            'errors' => new ViewErrorBag,
        ])->render();
        self::assertStringContainsString('Synthetic &lt;service&gt;', $html);
        self::assertStringContainsString('Synthetic verification evidence', $html);
        self::assertStringContainsString('Synthetic operator guidance', $html);
        self::assertStringNotContainsString('SSH connection last verified', $html);
        self::assertStringNotContainsString('WordPress authorization stored', $html);
        self::assertNull(app(TargetConnectorAdmin::class)->forType('synthetic_protocol'));
        self::assertNotContains('synthetic_protocol', app(TargetConnectorRegistry::class)->types());
    }

    /**
     * @param  list<Target>  $targets
     * @return array{array<string, array<string, mixed>>, array<int, array{query:string, bindings:array<int, mixed>, time:float}>}
     */
    private function presentWithQueries(array $targets): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();
        try {
            $result = app(TargetConnectorAdmin::class)->inventory($targets);
            $queries = DB::getQueryLog();
        } finally {
            DB::disableQueryLog();
        }

        return [$result, $queries];
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Presentation Owner', 'email' => uniqid('presenter-', true).'@example.test',
            'password' => 'password', 'role' => GatewayRole::Owner,
            'target_scope_mode' => TargetScopeMode::All, 'access_enabled' => true,
        ]);
    }

    private function target(string $id, string $connector): Target
    {
        return Target::query()->create([
            'target_id' => $id, 'display_name' => $id, 'connector_type' => $connector,
            'connection_state' => TargetConnectionState::Disconnected,
        ]);
    }
}
