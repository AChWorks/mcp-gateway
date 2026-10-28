<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\TargetConnectorFailure;
use App\Application\Targets\TargetConnectorResult;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Admin\TargetConnectionController;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use ReflectionMethod;
use Tests\TestCase;

final class ConnectorExternalAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_other_connector_can_reuse_generic_authorization_handoff_without_wordpress_branching(): void
    {
        $target = Target::query()->create([
            'target_id' => 'other-connector',
            'display_name' => 'Connector fixture',
            'connector_type' => 'ssh_direct',
        ]);
        $owner = User::query()->create([
            'name' => 'Test Owner',
            'email' => 'external-test-owner@example.test',
            'password' => 'Never used for a login in this isolated test.',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
        Route::middleware(['web', 'auth'])->post('/admin/__connector_result_fixture/{target:target_id}',
            static function (Target $target) {
                Gate::authorize(GatewayPermission::TargetsConnect->value, $target);

                // Exercise the single existing controller boundary without
                // modifying production registry entries or adding fake adapters.
                return (new ReflectionMethod(TargetConnectionController::class, 'result'))
                    ->invoke(app(TargetConnectionController::class), $target, new TargetConnectorResult(
                        redirectUrl: 'https://identity.example.test/consent?state=opaque&audience=other',
                        authorizedOrigin: 'https://identity.example.test',
                    ), 'connect');
            },
        );
        $this->actingAs($owner);

        $post = $this->post('/admin/__connector_result_fixture/'.$target->target_id)->assertStatus(303);
        $location = (string) $post->headers->get('Location');
        self::assertStringNotContainsString('identity.example.test', $location);
        self::assertStringNotContainsString('state=', $location);
        $staleSessionSnapshot = session()->get('admin.external_authorization_handoffs');
        self::assertIsArray($staleSessionSnapshot);

        $html = html_entity_decode($this->get($location)->assertOk()->getContent(), ENT_QUOTES | ENT_HTML5);
        self::assertStringContainsString(
            'content="0;url=https://identity.example.test/consent?state=opaque&audience=other"', $html,
        );
        self::assertStringContainsString('rel="noreferrer noopener"', $html);
        $this->get($location)->assertRedirect('/admin/targets/other-connector')
            ->assertSessionHasErrors('target');

        // Simulate a concurrent Admin request saving its pre-consumption
        // session snapshot after the handoff was already claimed.
        $this->withSession(['admin.external_authorization_handoffs' => $staleSessionSnapshot]);
        $this->get($location)->assertRedirect('/admin/targets/other-connector')
            ->assertSessionHasErrors('target');
    }

    public function test_shared_result_rejects_a_connector_origin_mismatch_before_issuing_any_handoff(): void
    {
        $target = Target::query()->create([
            'target_id' => 'unsafe-connector',
            'display_name' => 'Unsafe fixture',
            'connector_type' => 'ssh_direct',
        ]);
        $owner = User::query()->create([
            'name' => 'Test Owner',
            'email' => 'unsafe-test-owner@example.test',
            'password' => 'Never used for a login in this isolated test.',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);

        $this->actingAs($owner)->get('/admin/targets/'.$target->target_id)->assertOk();

        try {
            (new ReflectionMethod(TargetConnectionController::class, 'result'))
                ->invoke(app(TargetConnectionController::class), $target, new TargetConnectorResult(
                    redirectUrl: 'https://untrusted.example.test/consent?state=sensitive',
                    authorizedOrigin: 'https://verified.example.test',
                ), 'connect');
            self::fail('Unverified connector destination was accepted.');
        } catch (TargetConnectorFailure $exception) {
            self::assertSame('unsafe_authorization_destination', $exception->reason);
            self::assertStringNotContainsString('sensitive', $exception->getMessage());
        }
    }
}
