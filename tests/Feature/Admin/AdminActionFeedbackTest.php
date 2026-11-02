<?php

namespace Tests\Feature\Admin;

use App\Application\Targets\SshTargetConnectionService;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetGroup;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\MessageBag;
use Illuminate\Support\Str;
use Illuminate\Support\ViewErrorBag;
use RuntimeException;
use Tests\TestCase;

final class AdminActionFeedbackTest extends TestCase
{
    use RefreshDatabase;

    public function test_redirect_carries_operation_specific_feedback_token(): void
    {
        $target = Target::query()->create([
            'target_id' => 'feedback-route',
            'display_name' => 'Feedback route',
            'connector_type' => 'ssh_direct',
        ]);
        $target->forceFill(['operations_paused' => true])->save();
        $this->actingAs($this->owner());
        $response = $this->post(route('admin.targets.test', ['target' => $target->target_id]));
        $location = (string) $response->headers->get('Location');

        self::assertStringContainsString('_admin_feedback=', $location);
        $this->get($location)->assertOk()
            ->assertSee('Resume Target operations before starting a new connection test.');
    }

    public function test_native_verify_rejection_displays_immediately_on_target_and_is_not_replayed_elsewhere(): void
    {
        $target = Target::query()->create([
            'target_id' => 'feedback-ssh',
            'display_name' => 'Feedback SSH host',
            'connector_type' => 'ssh_direct',
        ]);
        $target->forceFill(['operations_paused' => true])->save();
        $this->actingAs($this->owner());

        // Paused Target verifies nothing remotely, but exercises the exact
        // production SSH Verify POST/PRG/error handling and session lifecycle.
        $first = $this->followingRedirects()->post(route('admin.targets.test', ['target' => $target->target_id]))
            ->assertOk()
            ->assertSee('id="admin-feedback"', false)
            ->assertSee('data-admin-feedback', false)
            ->assertSee('role="alert"', false)
            ->assertSee('Resume Target operations before starting a new connection test.');

        $xpath = $this->xpath((string) $first->getContent());
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="admin-feedback"][@autofocus][@tabindex="-1"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="admin-feedback"]//div[@role="alert"])'));

        $this->get('/admin/targets')->assertOk()->assertDontSee('id="admin-feedback"', false)
            ->assertDontSee('Resume Target operations before starting a new connection test.');
    }

    public function test_native_success_feedback_on_same_target_redirect_is_one_shot(): void
    {
        $target = Target::query()->create([
            'target_id' => 'feedback-toggle',
            'display_name' => 'Feedback toggle',
            'connector_type' => 'ssh_direct',
        ]);
        $this->actingAs($this->owner());

        $this->followingRedirects()->post(route('admin.targets.operations.update', ['target' => $target->target_id]), ['state' => 'paused'])
            ->assertOk()->assertSee('id="admin-feedback"', false)
            ->assertSee('role="status"', false)
            ->assertSee('Target operations paused. Connection, credentials and permissions are preserved.');

        $this->get(route('admin.targets.show', ['target' => $target->target_id]))
            ->assertOk()->assertDontSee('id="admin-feedback"', false)
            ->assertDontSee('Target operations paused. Connection, credentials and permissions are preserved.');
    }

    public function test_framework_validation_redirect_after_success_is_not_hidden_by_previous_session_result(): void
    {
        $target = Target::query()->create([
            'target_id' => 'feedback-mixed-operations',
            'display_name' => 'Mixed operations',
            'connector_type' => 'ssh_direct',
        ]);
        $this->actingAs($this->owner());
        $successful = $this->post(route('admin.targets.operations.update', ['target' => $target->target_id]), [
            'state' => 'paused',
        ])->assertAdminRedirect(route('admin.targets.show', ['target' => $target->target_id]));
        $this->get((string) $successful->headers->get('Location'))->assertOk()
            ->assertSee('Target operations paused.');

        // A fast second native POST can send the prior feedback URL as
        // Referer before deferred JavaScript clears its old query token.
        $failed = $this->from('/admin/operations?search=trailing%20space%20&empty=&_admin_feedback='.str_repeat('f', 40))
            ->put('/admin/operations', [
                'version' => '0',
                'values' => ['wp_response_kib' => '999999', 'wp_readonly_response_kib' => '256'],
                'current_password' => 'CorrectHorse!234',
            ])->assertAdminRedirect('/admin/operations?search=trailing%20space%20&empty=')
            ->assertSessionHasErrors('values.wp_response_kib');

        $location = (string) $failed->headers->get('Location');
        self::assertStringContainsString('_admin_feedback=', $location);
        $this->get('/admin/targets')->assertOk()
            ->assertDontSee('id="admin-feedback"', false);
        $this->get($location)->assertOk()
            ->assertSee('value="999999"', false)
            ->assertSee('aria-invalid="true"', false)
            ->assertSee('The values.wp response kib field must not be greater than')
            ->assertDontSee('Target operations paused.');
        $this->get($location)->assertOk()
            ->assertDontSee('The values.wp response kib field must not be greater than');
    }

    public function test_cache_write_failure_keeps_native_flash_fallback_even_after_earlier_result(): void
    {
        $target = Target::query()->create([
            'target_id' => 'feedback-cache-fallback',
            'display_name' => 'Feedback fallback',
            'connector_type' => 'ssh_direct',
        ]);
        $this->actingAs($this->owner())->withSession([
            'admin.feedback.routed_until' => time() + 600,
        ]);
        Cache::shouldReceive('put')->once()->andReturn(false);

        $result = $this->post(route('admin.targets.operations.update', ['target' => $target->target_id]), [
            'state' => 'paused',
        ])->assertAdminRedirect(route('admin.targets.show', ['target' => $target->target_id]))
            ->assertSessionHas('status');
        self::assertStringNotContainsString('_admin_feedback=', (string) $result->headers->get('Location'));

        $this->get(route('admin.targets.show', ['target' => $target->target_id]))
            ->assertOk()
            ->assertSee('Target operations paused. Connection, credentials and permissions are preserved.');
    }

    public function test_shared_summary_covers_all_field_errors_and_safe_diagnostic_context(): void
    {
        $errors = new ViewErrorBag;
        $errors->put('default', new MessageBag([
            'name' => ['Name is required.'],
            'current_password' => ['Password is not valid.'],
            'target' => ['Name is required.'],
        ]));
        $this->actingAs($this->owner())->withSession([
            'errors' => ['default' => ['messages' => $errors->getBag('default')->messages(), 'format' => ':message']],
            'diagnostic_code' => 'invalid_ssh_host_key',
            'diagnostic_stage' => 'admission',
            'diagnostic_reference' => 'fixture-reference',
        ]);
        $page = $this->get('/admin/targets')->assertOk()
            ->assertSee('The action needs attention.')
            ->assertSee('Password is not valid.')
            ->assertSee('invalid_ssh_host_key')
            ->assertSee('fixture-reference')
            ->assertSee('What to check');

        $xpath = $this->xpath((string) $page->getContent());
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="admin-feedback"]//div[@role="alert"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="admin-feedback"]//li[text()="Name is required."])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="admin-feedback"]//li[text()="Password is not valid."])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="admin-feedback"]//section[@aria-label="Operation diagnostic"])'));
    }

    public function test_rejection_outweighs_conflicting_stale_success_in_shared_feedback(): void
    {
        $this->actingAs($this->owner())->withSession([
            'status' => 'Operation saved.',
            'errors' => ['default' => ['messages' => [
                'configuration' => ['The submitted configuration was rejected.'],
            ], 'format' => ':message']],
        ]);

        $this->get('/admin/operations')->assertOk()
            ->assertSee('The submitted configuration was rejected.')
            ->assertDontSee('Operation saved.')
            ->assertSee('The action needs attention.');
    }

    public function test_preflight_validation_owns_its_error_and_never_claims_registration_failure(): void
    {
        $this->actingAs($this->owner());
        $this->followingRedirects()->post(route('admin.targets.preflight'), ['connector_type' => 'ssh_direct'])
            ->assertOk()
            ->assertSee('id="target-registration-errors"', false)
            ->assertSee('data-admin-feedback', false)
            ->assertSee('Endpoint check could not be completed.')
            ->assertDontSee('Target was not registered.')
            ->assertDontSee('id="admin-feedback"', false);
    }

    public function test_group_selection_error_has_one_primary_alert_in_local_context(): void
    {
        $group = TargetGroup::query()->create(['name' => 'Feedback group']);
        $this->actingAs($this->owner())->withSession([
            'errors' => ['default' => ['messages' => [
                'selection' => ['Select at least one item to review.'],
            ], 'format' => ':message']],
        ]);

        $response = $this->get('/admin/target-groups/'.$group->getKey().'/targets?membership=available&intent=add')
            ->assertOk()
            ->assertDontSee('id="admin-feedback"', false);
        $xpath = $this->xpath((string) $response->getContent());

        self::assertSame(1, (int) $xpath->evaluate('count(//main//div[@role="alert"][@data-admin-feedback])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//main//div[@role="alert"]//li[text()="Select at least one item to review."])'));
        self::assertSame(1, substr_count((string) $response->getContent(), 'Select at least one item to review.'));
        self::assertSame(1, (int) $xpath->evaluate('count(//section[@aria-labelledby="access-members-title"]/div[contains(@class,"alert")]/following-sibling::form)'));
    }

    public function test_actual_ssh_registration_rejection_keeps_safe_diagnostic_summary_and_stage(): void
    {
        $this->actingAs($this->owner());
        $result = $this->post(route('admin.targets.store'), [
            'connector_type' => 'ssh_direct',
            'target_id' => 'feedback-invalid-pin',
            'display_name' => 'Invalid SSH pin fixture',
            'ssh_host' => 'example.test',
            'ssh_port' => 22,
            'ssh_username' => 'deploy',
            'ssh_host_key' => 'ssh-ed25519 malformed',
            'ssh_auth_method' => 'password',
            'ssh_password' => 'not-a-real-login-secret',
            'ssh_trust_confirmed' => 'yes',
        ])->assertSessionHas('diagnostic_code', 'invalid_ssh_host_key')
            ->assertSessionHas('diagnostic_context', static fn (array $context): bool => ($context['failure_stage'] ?? null) === 'operation')
            ->assertSessionHas('diagnostic_reference', static fn (string $value): bool => Str::isUuid($value));

        $body = $this->get((string) $result->headers->get('Location'))
            ->assertOk()
            ->assertSee('id="target-registration-errors"', false)
            ->assertSee('Diagnostic category')
            ->assertSee('invalid_ssh_host_key')
            ->assertSee('Failure stage')
            ->assertSee('operation')
            ->assertSee('What to check')
            ->assertSee('Log reference')
            ->assertDontSee('not-a-real-login-secret')
            ->assertDontSee('id="admin-feedback"', false)
            ->getContent();

        $xpath = $this->xpath((string) $body);
        self::assertSame(1, (int) $xpath->evaluate('count(//div[@id="target-registration-errors"]//code[text()="invalid_ssh_host_key"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//div[@id="target-registration-errors"]//code[text()="operation"])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//main//*[@role="alert"][@data-admin-feedback])'));
    }

    public function test_unexpected_ssh_verify_error_uses_operation_aware_guidance_without_raw_exception(): void
    {
        $target = Target::query()->create([
            'target_id' => 'feedback-verify-fault',
            'display_name' => 'SSH verify fault injection',
            'connector_type' => 'ssh_direct',
        ]);
        $this->app->instance(SshTargetConnectionService::class, new class
        {
            public function test(Target $target): never
            {
                throw new RuntimeException('password=LOCAL_TEST_SECRET');
            }
        });
        $this->actingAs($this->owner());
        $result = $this->post(route('admin.targets.test', ['target' => $target->target_id]))
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'operation_unconfirmed')
            ->assertSessionHas('diagnostic_stage', 'operation')
            ->assertSessionHas('diagnostic_reference', static fn (string $value): bool => Str::isUuid($value));

        $this->get((string) $result->headers->get('Location'))
            ->assertOk()
            ->assertSee('SSH verification did not complete reliably.')
            ->assertSee('No remote command or credential revocation was requested.')
            ->assertSee('operation_unconfirmed')
            ->assertSee('Failure stage')
            ->assertSee('Log reference')
            ->assertDontSee('LOCAL_TEST_SECRET')
            ->assertDontSee('Do not repeat an uncertain remote revoke');
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Feedback fixture owner',
            'email' => 'feedback-'.uniqid().'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => GatewayRole::Owner->value,
            'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true,
        ]);
    }

    private function xpath(string $html): \DOMXPath
    {
        $document = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        return new \DOMXPath($document);
    }
}
