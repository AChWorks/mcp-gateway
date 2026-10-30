<?php

namespace Tests\Feature\Admin;

use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Models\User;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

final class TargetFieldAccessibilityTest extends TestCase
{
    use RefreshDatabase;

    public function test_invalid_native_enrollment_links_each_error_and_existing_help_to_its_control(): void
    {
        Http::preventStrayRequests();
        $this->actingAs($this->owner())
            ->from('/admin/targets/create?connector_type=ssh_direct')
            ->post('/admin/targets', [
                'connector_type' => 'ssh_direct', 'target_id' => '', 'display_name' => '',
                'ssh_host' => '', 'ssh_port' => 0, 'ssh_username' => '',
                'ssh_host_key' => '', 'ssh_auth_method' => 'invalid',
            ])
            ->assertRedirect('/admin/targets/create?connector_type=ssh_direct')
            ->assertSessionHasErrors(['target_id', 'display_name', 'ssh_host', 'ssh_port', 'ssh_host_key', 'ssh_auth_method']);
        $response = $this->withCookie(session()->getName(), session()->getId())
            ->get('/admin/targets/create?connector_type=ssh_direct')->assertOk();
        $xpath = $this->document((string) $response->getContent());
        foreach (['target_id', 'display_name', 'ssh_host', 'ssh_port', 'ssh_username', 'ssh_host_key', 'ssh_auth_method', 'ssh_trust_confirmed'] as $id) {
            $this->assertFieldError($xpath, $id);
        }
        $this->assertDescription($xpath, 'target_id', 'target_id-help');
        $this->assertDescription($xpath, 'ssh_host_key', 'ssh-host-key-help');
        $this->assertDescription($xpath, 'ssh_auth_method', 'ssh_auth_help');
        self::assertSame(0, Target::query()->count());
        Http::assertNothingSent();
    }

    public function test_invalid_native_configuration_uses_control_ids_rather_than_request_names(): void
    {
        Http::preventStrayRequests();
        $this->actingAs($this->owner());
        $hostKey = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32));
        app(SshTargetRegistration::class)->register(
            'field-editor', 'Field editor', '1.1.1.1', 22, 'deploy', $hostKey,
            'password', 'isolated-test-secret', null,
        );
        $this->from('/admin/targets/field-editor/edit')
            ->put('/admin/targets/field-editor/configuration', [
                'configuration_revision' => '', 'ssh_host' => '', 'ssh_port' => 0,
                'ssh_username' => '', 'ssh_host_key' => '',
            ])->assertRedirect('/admin/targets/field-editor/edit')
            ->assertSessionHasErrors(['configuration_revision', 'ssh_host', 'ssh_port', 'ssh_username', 'ssh_host_key']);
        $response = $this->withCookie(session()->getName(), session()->getId())
            ->get('/admin/targets/field-editor/edit')->assertOk()->assertDontSee('isolated-test-secret');
        $xpath = $this->document((string) $response->getContent());
        foreach (['ssh_edit_host', 'ssh_edit_port', 'ssh_edit_username', 'ssh_edit_host_key'] as $id) {
            $this->assertFieldError($xpath, $id);
        }
        $this->assertDescription($xpath, 'ssh_edit_host_key', 'ssh-edit-host-key-help');
        $this->assertDescription($xpath, 'ssh-reconfiguration', 'ssh-configuration-revision-error');
        self::assertSame('1.1.1.1', DB::table('ssh_direct_target_configs')->value('host'));
        Http::assertNothingSent();
    }

    public function test_recovery_and_forget_forms_keep_repeated_password_error_ids_unique_on_one_page(): void
    {
        Http::preventStrayRequests();
        $target = Target::query()->create([
            'target_id' => 'field-recovery', 'display_name' => 'Field recovery',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => TargetConnectionState::Connected,
        ]);
        $credential = TargetCredential::query()->create([
            'target_record_id' => $target->getKey(), 'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth', 'encrypted_payload' => 'opaque-isolated-fixture',
        ]);
        $intent = (string) Str::ulid();
        DB::table('wp_ai_bridge_refresh_intents')->insert([
            'id' => $intent, 'target_record_id' => $target->getKey(),
            'credential_id' => $credential->getKey(), 'generation' => 1, 'attempts' => 1,
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->actingAs($this->owner())->from('/admin/targets/field-recovery')
            ->post('/admin/targets/field-recovery/reconcile-refresh', [
                'intent_id' => $intent, 'confirm_target_id' => 'field-recovery',
                'wordpress_client_revoked' => 'yes', 'other_clients_affected' => 'yes',
                'current_password' => 'wrong-password',
            ])->assertRedirect('/admin/targets/field-recovery')->assertSessionHasErrors('current_password');
        $response = $this->withCookie(session()->getName(), session()->getId())
            ->get('/admin/targets/field-recovery')->assertOk()->assertDontSee('wrong-password');
        $xpath = $this->document((string) $response->getContent());
        $this->assertFieldError($xpath, 'reconcile_refresh_password');
        $this->assertFieldError($xpath, 'forget_owner_password');
        self::assertSame(2, (int) $xpath->evaluate('count(//input[@name="current_password"])'));
        self::assertSame(1, DB::table('wp_ai_bridge_refresh_intents')->count());
        self::assertSame(1, TargetCredential::query()->count());
        Http::assertNothingSent();
    }

    private function document(string $html): DOMXPath
    {
        $dom = new DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $xpath = new DOMXPath($dom);
        $ids = [];
        foreach ($xpath->query('//*[@id]') as $element) {
            $ids[] = $element->getAttribute('id');
        }
        self::assertCount(count($ids), array_unique($ids), 'Rendered IDs must be unique across separate forms.');

        return $xpath;
    }

    private function assertFieldError(DOMXPath $xpath, string $id): void
    {
        $control = $xpath->query('//*[@id="'.$id.'"]')->item(0);
        self::assertInstanceOf(DOMElement::class, $control);
        self::assertSame('true', $control->getAttribute('aria-invalid'), $control->ownerDocument->saveHTML($control));
        $this->assertDescription($xpath, $id, $id.'-error');
        $error = $xpath->query('//*[@id="'.$id.'-error"]')->item(0);
        self::assertInstanceOf(DOMElement::class, $error);
        self::assertSame('alert', $error->getAttribute('role'));
        self::assertNotSame('', trim($error->textContent));
        self::assertGreaterThan(0, (int) $xpath->evaluate(
            'count(//label[@for="'.$id.'"] | //*[@id="'.$id.'"]/ancestor::label)',
        ));
    }

    private function assertDescription(DOMXPath $xpath, string $id, string $expected): void
    {
        $control = $xpath->query('//*[@id="'.$id.'"]')->item(0);
        self::assertInstanceOf(DOMElement::class, $control);
        $tokens = preg_split('/\s+/', trim($control->getAttribute('aria-describedby')));
        self::assertContains($expected, $tokens, $id);
        foreach ($tokens as $token) {
            self::assertSame(1, (int) $xpath->evaluate('count(//*[@id="'.$token.'"])'), $id.' → '.$token);
        }
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'Field Owner', 'email' => 'field-owner@example.test', 'password' => 'password',
            'role' => GatewayRole::Owner, 'target_scope_mode' => TargetScopeMode::All, 'access_enabled' => true,
        ]);
    }
}
