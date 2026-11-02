<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\MessageBag;
use Illuminate\Support\ViewErrorBag;
use Tests\TestCase;

final class AdminActionFeedbackTest extends TestCase
{
    use RefreshDatabase;

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
