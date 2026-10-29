<?php

namespace Tests\Feature\Admin;

use App\Application\Access\AccessControl;
use App\Application\Access\UserAccessManager;
use App\Application\Targets\TargetInventory;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

final class TargetManagementAdminTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
            }
        });

        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => $this->metadata($request));
    }

    public function test_owner_can_browse_generic_targets_and_register_valid_wordpress_without_creating_credentials(): void
    {
        $owner = $this->user('owner', 'all');
        $ssh = $this->target('ssh-demo', 'ssh_direct', '<script>alert(1)</script>');

        $this->actingAs($owner)->get('/admin/')->assertOk()
            ->assertSee('Registered Targets');
        $this->get('/admin/targets')->assertOk()
            ->assertSee('ssh-demo')->assertDontSee('<script>alert(1)</script>', false)
            ->assertSee('ssh_direct');
        $this->get('/admin/targets/'.$ssh->target_id)->assertOk()
            ->assertSee('ssh-demo');
        $this->get('/admin/targets/create')->assertOk()
            ->assertSee('Stable Target ID')->assertSee('wp_ai_bridge');

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'wp-blog',
            'display_name' => 'WordPress blog',
            'ai_guidance' => 'Production WordPress: explain consequences before changing content.',
            'base_url' => 'https://wordpress.example.test/',
        ])->assertRedirect('/admin/targets/wp-blog');

        $wp = Target::query()->where('target_id', 'wp-blog')->firstOrFail();
        self::assertSame('wp_ai_bridge', $wp->connector_type);
        self::assertSame('Production WordPress: explain consequences before changing content.', $wp->ai_guidance);
        self::assertSame('https://wordpress.example.test', WpAiBridgeTargetConfig::query()
            ->where('target_record_id', $wp->getKey())->value('base_url'));
        self::assertSame(0, DB::table('target_credentials')->count());
        $this->get('/admin/targets/wp-blog')->assertOk()
            ->assertSee('Production WordPress: explain consequences before changing content.')
            ->assertSee('WordPress blog')
            ->assertSee('https://wordpress.example.test')
            ->assertSee('Authorize this Target to connect WordPress securely');
    }

    public function test_new_target_is_a_single_connector_first_form_with_server_rendered_no_js_fallback(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        foreach ([
            ['', '', true, true],
            ['?connector_type=wp_ai_bridge', 'wp_ai_bridge', false, true],
            ['?connector_type=ssh_direct', 'ssh_direct', true, false],
            ['?connector_type=ai_server_agent', '', true, true],
        ] as [$query, $selected, $wpDisabled, $sshDisabled]) {
            $html = $this->get('/admin/targets/create'.$query)->assertOk()->getContent();
            $dom = new \DOMDocument;
            $previous = libxml_use_internal_errors(true);
            $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
            $xpath = new \DOMXPath($dom);
            self::assertSame(1, (int) $xpath->evaluate('count(//form[@id="target-create-form"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//select[@name="connector_type"])'));
            self::assertSame(0, (int) $xpath->evaluate('count(//option[@value="ai_server_agent"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//input[@name="target_id"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//input[@name="display_name"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//fieldset[@data-target-shared]//textarea[@name="ai_guidance"][@maxlength="800"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//input[@name="ssh_password"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//textarea[@name="ssh_private_key"])'));
            self::assertSame(0, (int) $xpath->evaluate('count(//option[@value="both"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//input[@name="ssh_host_key" or @id="ssh_host_key"] | //textarea[@name="ssh_host_key"])'));
            self::assertSame(1, (int) $xpath->evaluate('count(//textarea[@id="ssh_host_key"][@required])'));
            self::assertSame($selected === '' ? 0 : 1,
                (int) $xpath->evaluate('count(//select[@id="connector_type"]/option[@selected])'));
            if ($selected !== '') {
                self::assertSame($selected, $xpath->evaluate('string(//select[@id="connector_type"]/option[@selected]/@value)'));
            }
            self::assertSame($wpDisabled ? 1 : 0, (int) $xpath->evaluate('count(//fieldset[@data-connector-panel="wp_ai_bridge"][@disabled])'));
            self::assertSame($sshDisabled ? 1 : 0, (int) $xpath->evaluate('count(//fieldset[@data-connector-panel="ssh_direct"][@disabled])'));
            self::assertSame(1, (int) $xpath->evaluate(
                'count(//div[@data-target-actions]//button[@formnovalidate][@formaction])',
            ));
            self::assertStringContainsString('How to obtain and verify the server host key', $html);
            self::assertStringContainsString('ssh_host_rsa_key.pub', $html);
            self::assertStringContainsString('ssh_host_ed25519_key.pub', $html);
        }
    }

    public function test_unrecognized_stored_connector_cannot_execute_or_be_filtered_as_supported(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        $target = $this->target('unsupported-record', 'ssh_direct');
        DB::table('targets')->where('id', $target->getKey())
            ->update(['connector_type' => 'unrecognized_connector']);

        $this->get('/admin/targets/'.$target->target_id)
            ->assertOk()
            ->assertSee('This connector is not yet available for enrollment.');

        foreach (['connect', 'reconnect', 'disconnect', 'test'] as $action) {
            $this->post(route('admin.targets.'.$action, ['target' => $target->target_id], false))
                ->assertRedirect('/admin/targets/'.$target->target_id)
                ->assertSessionHasErrors('target');
        }

        Http::assertNothingSent();
        $this->expectException(\InvalidArgumentException::class);
        app(TargetInventory::class)
            ->mcpPage($this->user('owner', 'all'), connectorType: 'unrecognized_connector');
    }

    public function test_selected_scope_operator_cannot_discover_other_target_or_enroll_new_connector(): void
    {
        $visible = $this->target('visible', 'wp_ai_bridge');
        $hidden = $this->target('hidden', 'ssh_direct');
        $operator = $this->user('operator', 'selected');
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $visible->getKey(),
            'allowed' => true,
        ]);

        $this->actingAs($operator)->get('/admin/targets')->assertOk()
            ->assertSee('visible')->assertDontSee('admin/targets/hidden');
        $this->get('/admin/')->assertOk()->assertSee('Registered Targets');
        $this->get('/admin/targets/'.$visible->target_id)->assertOk();
        $this->get('/admin/targets/'.$hidden->target_id)->assertForbidden();
        $this->get('/admin/targets/create')->assertForbidden();
        $this->post('/admin/targets', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'unexpected',
            'display_name' => 'SSH',
            'base_url' => 'https://wordpress.example.test',
        ])->assertForbidden();

        Http::assertNothingSent();
        self::assertSame(2, Target::query()->count());
    }

    public function test_selected_administrator_cannot_expand_ssh_or_wordpress_target_scope_by_registration(): void
    {
        $owner = $this->user('owner', 'all');
        $this->actingAs($owner)->post('/admin/users', [
            'name' => 'Selected SSH administrator',
            'email' => 'selected-ssh-admin@example.test',
            'password' => 'DifferentHorse!234',
            'password_confirmation' => 'DifferentHorse!234',
            'role' => 'administrator',
            'target_scope_mode' => 'selected',
            'access_enabled' => '1',
            'ssh_permissions_reviewed' => '1',
            'confirm_ssh_permission_changes' => '1',
            'denied_permissions' => [
                GatewayPermission::SshFileRead->value,
                GatewayPermission::SshFileWrite->value,
            ],
            'current_password' => 'ThisIsATestSecret!234',
        ])->assertRedirect()->assertSessionHasNoErrors();

        $admin = User::query()->where('email', 'selected-ssh-admin@example.test')->sole();
        $access = app(AccessControl::class);
        self::assertTrue($access->allows($admin, GatewayPermission::TargetsCreate));
        self::assertTrue($access->allows($admin, GatewayPermission::SshCommandRun));
        $this->assertDatabaseMissing('user_permission_denials', [
            'user_id' => $admin->getKey(),
            'permission' => GatewayPermission::SshCommandRun->value,
        ]);

        $hostKey = 'ssh-ed25519 '.base64_encode(
            pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32),
        );
        $newTargets = [
            'ssh-new-admin' => [
                'connector_type' => 'ssh_direct',
                'target_id' => 'ssh-new-admin',
                'display_name' => 'SSH newly enrolled',
                'ssh_host' => '1.1.1.1',
                'ssh_port' => 22,
                'ssh_username' => 'deploy',
                'ssh_host_key' => $hostKey,
                'ssh_auth_method' => 'password',
                'ssh_password' => 'test-credential-not-a-server-password',
                'ssh_trust_confirmed' => 'yes',
            ],
            'wp-new-admin' => [
                'connector_type' => 'wp_ai_bridge',
                'target_id' => 'wp-new-admin',
                'display_name' => 'WordPress newly enrolled',
                'base_url' => 'https://wordpress.example.test/',
            ],
        ];

        $this->actingAs($admin);
        foreach ($newTargets as $id => $payload) {
            $this->post('/admin/targets', $payload)
                ->assertRedirect('/admin/targets')->assertSessionHasNoErrors()
                ->assertSessionHas('status', static fn (string $message): bool => str_contains($message, $id) && str_contains($message, 'Ask an Owner'));
            $created = Target::query()->where('target_id', $id)->sole();
            $this->assertDatabaseMissing('user_target_access', [
                'user_id' => $admin->getKey(),
                'target_record_id' => $created->getKey(),
                'allowed' => true,
            ]);
            self::assertFalse($access->allows($admin, GatewayPermission::TargetsView, $created));
            $this->get('/admin/targets/'.$id)->assertForbidden();
        }

        $ssh = Target::query()->where('target_id', 'ssh-new-admin')->sole();
        $wordpress = Target::query()->where('target_id', 'wp-new-admin')->sole();
        self::assertFalse($access->allows($admin, GatewayPermission::SshCommandRun, $ssh));
        $this->get('/admin/targets')->assertOk()
            ->assertDontSee('ssh-new-admin')->assertDontSee('wp-new-admin');

        $targetRule = '/admin/users/'.$admin->getKey().'/targets/'.$ssh->target_id;
        $this->actingAs($owner)->put($targetRule, [
            'access_rule' => 'allow',
            'current_password' => 'ThisIsATestSecret!234',
        ])->assertSessionHasErrors('confirm_ssh_target_changes');
        self::assertFalse($access->allows($admin, GatewayPermission::SshCommandRun, $ssh));

        $this->put($targetRule, [
            'access_rule' => 'allow',
            'current_password' => 'ThisIsATestSecret!234',
            'confirm_ssh_target_changes' => '1',
            'target_revision' => app(UserAccessManager::class)->targetRuleRevision($admin, $ssh),
        ])->assertRedirect()->assertSessionHasNoErrors();
        $this->assertDatabaseHas('user_target_access', [
            'user_id' => $admin->getKey(),
            'target_record_id' => $ssh->getKey(),
            'allowed' => true,
        ]);
        self::assertTrue($access->allows($admin, GatewayPermission::SshCommandRun, $ssh));
        self::assertFalse($access->allows($admin, GatewayPermission::SshFileRead, $ssh));
        self::assertFalse($access->allows($admin, GatewayPermission::TargetsView, $wordpress));
        $this->actingAs($admin)->get('/admin/targets/'.$ssh->target_id)->assertOk();
    }

    public function test_admin_registration_rejects_unreviewed_connector_and_non_https_or_unsafe_target(): void
    {
        $this->actingAs($this->user('owner', 'all'));

        $this->post('/admin/targets', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'unauthorized',
            'display_name' => 'Unreviewed',
            'base_url' => 'https://wordpress.example.test',
        ])->assertSessionHasErrors('ssh_host');

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'bad-http',
            'display_name' => 'Unreviewed',
            'base_url' => 'http://wordpress.example.test',
        ])->assertSessionHasErrors('base_url');

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'bad-target',
            'display_name' => 'Private network',
            'base_url' => 'https://127.0.0.1',
        ])->assertSessionHasErrors('base_url');

        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
    }

    public function test_wordpress_registration_shows_the_actual_blocked_address_and_a_remedy(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'blinko.example.test' ? ['1.1.1.1', '127.0.0.1'] : ['1.1.1.1'];
            }
        });

        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'blinko',
            'display_name' => 'Blinko',
            'base_url' => 'https://blinko.example.test',
        ])->assertSessionHasErrors('base_url')
            ->assertSessionHas('diagnostic_code', 'unsafe_target')
            ->assertSessionHas('diagnostic_context', static fn (array $details): bool => ($details['outbound_rejection_reason'] ?? null) === 'dns_non_public'
                && ($details['outbound_rejected_address'] ?? null) === '127.0.0.1'
                && ($details['outbound_address_class'] ?? null) === 'loopback'
            );

        $this->get('/admin/targets/create?connector_type=wp_ai_bridge')->assertOk()
            ->assertSee('127.0.0.1')
            ->assertSee('/etc/hosts')
            ->assertSee('Do not bypass SSRF protections.');

        self::assertSame(0, Target::query()->count());
        Http::assertNothingSent();
    }

    public function test_dns_preflight_is_read_only_and_shows_the_actual_gateway_loopback_override(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'blinko.example.test' ? ['127.0.0.1'] : ['1.1.1.1'];
            }
        });

        $this->post('/admin/targets/preflight', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'blinko',
            'display_name' => 'Blinko',
            'base_url' => 'https://blinko.example.test/',
            'ssh_password' => 'NEVER_FLASH_SECRET',
        ])->assertRedirect('/admin/targets/create?connector_type=wp_ai_bridge');

        $result = session('target_endpoint_preflight');
        self::assertIsArray($result);
        self::assertFalse($result['ok']);
        self::assertStringContainsString('127.0.0.1', $result['message']);
        self::assertStringContainsString('/etc/hosts', $result['next_step']);
        self::assertTrue(Str::isUuid($result['reference']));
        self::assertArrayNotHasKey('ssh_password', session()->getOldInput());

        $this->get('/admin/targets/create?connector_type=wp_ai_bridge')
            ->assertOk()
            ->assertSee('Gateway endpoint preflight')
            ->assertSee('127.0.0.1')
            ->assertSee('/etc/hosts')
            ->assertDontSee('NEVER_FLASH_SECRET');

        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
    }

    public function test_dns_preflight_public_success_is_not_an_enrollment_or_bridge_check(): void
    {
        $this->actingAs($this->user('owner', 'all'));

        $this->post('/admin/targets/preflight', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'should-not-register',
            'display_name' => 'A test',
            'base_url' => 'https://wordpress.example.test/',
        ])->assertRedirect('/admin/targets/create?connector_type=wp_ai_bridge');

        $result = session('target_endpoint_preflight');
        self::assertIsArray($result);
        self::assertTrue($result['ok']);
        self::assertSame('wp_ai_bridge', $result['checked_connector']);
        self::assertSame('https://wordpress.example.test/', $result['checked_subject']);
        self::assertSame(['base_url' => 'https://wordpress.example.test/'], $result['checked_fields']);
        self::assertStringContainsString('1.1.1.1', $result['message']);
        $this->get('/admin/targets/create?connector_type=wp_ai_bridge')
            ->assertOk()
            ->assertSee('Actual connections independently recheck DNS');
        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
    }

    public function test_numeric_https_preflight_success_does_not_claim_dns_resolution_in_admin(): void
    {
        $this->actingAs($this->user('owner', 'all'));

        $dns = new class implements DnsResolver
        {
            public int $calls = 0;

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                $this->calls++;

                throw new \RuntimeException('Numeric URL should not invoke the DNS resolver.');
            }
        };
        $this->app->instance(DnsResolver::class, $dns);

        $url = 'https://8.8.8.8/wordpress';
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'numeric-https-check',
            'display_name' => 'Public numeric HTTPS',
            'base_url' => $url,
        ])->assertRedirect('/admin/targets/create?connector_type=wp_ai_bridge');

        self::assertSame(0, $dns->calls);
        $result = session('target_endpoint_preflight');
        self::assertIsArray($result);
        self::assertTrue($result['ok']);
        self::assertSame($url, $result['checked_subject']);
        self::assertSame(['base_url' => $url], $result['checked_fields']);
        self::assertSame('wp_ai_bridge', $result['checked_connector']);
        self::assertStringContainsString('approved these public HTTPS destination addresses', $result['message']);
        self::assertStringNotContainsString('resolved', strtolower($result['message']));
        self::assertStringContainsString('does not verify TLS', $result['limitation']);
        self::assertStringContainsString('remote service identity', $result['limitation']);
        self::assertStringContainsString('authentication', $result['limitation']);

        $this->get('/admin/targets/create?connector_type=wp_ai_bridge')
            ->assertOk()
            ->assertSee('Checked endpoint')
            ->assertSee($url)
            ->assertSee('Gateway approved these public HTTPS destination addresses')
            ->assertSee('DNS is checked for hostnames')
            ->assertDontSee('Gateway resolved this public HTTPS destination')
            ->assertSee('does not verify TLS')
            ->assertSee('remote service identity')
            ->assertSee('authentication');

        self::assertSame(0, $dns->calls);
        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
        self::assertSame(0, WpAiBridgeTargetConfig::query()->count());
    }

    public function test_endpoint_preflight_requires_authentication_and_connector_specific_schema(): void
    {
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'wp_ai_bridge',
            'base_url' => 'https://wordpress.example.test',
        ])->assertRedirect('/admin/login');

        $this->actingAs($this->user('viewer', 'all'))->post('/admin/targets/preflight', [
            'connector_type' => 'wp_ai_bridge',
            'base_url' => 'https://wordpress.example.test',
        ])->assertForbidden();

        $this->actingAs($this->user('owner', 'all'));
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'ssh_direct',
            'base_url' => 'https://wordpress.example.test',
        ])->assertSessionHasErrors('ssh_host');
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'unimplemented_connector',
            'base_url' => 'https://wordpress.example.test',
        ])->assertSessionHasErrors('connector_type');
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'wp_ai_bridge',
            'base_url' => 'http://wordpress.example.test',
            'ssh_password' => 'DO_NOT_FLASH_PASSWORD',
            'ssh_private_key' => 'DO_NOT_FLASH_PRIVATE_KEY',
            'future_secret' => 'DO_NOT_FLASH_OTHER_SECRET',
        ])->assertSessionHasErrors('base_url');

        $old = session()->getOldInput();
        foreach (['ssh_password', 'ssh_private_key', 'future_secret'] as $secret) {
            self::assertArrayNotHasKey($secret, $old);
        }
        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
    }

    public function test_ssh_preflight_uses_ssh_policy_without_host_key_login_or_registration(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'ssh-check',
            'display_name' => 'SSH check',
            'ssh_host' => '8.8.8.8',
            'ssh_port' => '2222',
            'ssh_username' => 'deploy',
            'ssh_host_key' => 'ssh-ed25519 PUBLIC_KEY_FIXTURE',
            'ssh_auth_method' => 'private_key',
            'ssh_trust_confirmed' => 'yes',
            'ssh_private_key' => 'NEVER_FLASH_SSH_PRIVATE_KEY',
            'ssh_password' => 'NEVER_FLASH_SSH_PASSWORD',
            'ssh_passphrase' => 'NEVER_FLASH_SSH_PASSPHRASE',
            'secret_unknown' => 'NEVER_FLASH_UNKNOWN_SECRET',
        ])->assertRedirect('/admin/targets/create?connector_type=ssh_direct');

        $result = session('target_endpoint_preflight');
        self::assertIsArray($result);
        self::assertTrue($result['ok']);
        self::assertSame('ssh_direct', $result['checked_connector']);
        self::assertSame('8.8.8.8:2222', $result['checked_subject']);
        self::assertSame(['ssh_host' => '8.8.8.8', 'ssh_port' => '2222'], $result['checked_fields']);
        self::assertStringContainsString('8.8.8.8', $result['message']);
        self::assertStringContainsString('host key', $result['limitation']);
        foreach (['ssh_private_key', 'ssh_password', 'ssh_passphrase', 'secret_unknown'] as $secret) {
            self::assertArrayNotHasKey($secret, session()->getOldInput());
        }
        $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()
            ->assertSee('Gateway endpoint preflight')
            ->assertSee('8.8.8.8')
            ->assertSee('Checked endpoint')
            ->assertSee('host key')
            ->assertDontSee('NEVER_FLASH_SSH_PRIVATE_KEY')
            ->assertDontSee('NEVER_FLASH_SSH_PASSWORD');

        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
        self::assertSame(0, DB::table('target_credentials')->count());
    }

    public function test_ssh_preflight_rejects_loopback_and_records_actionable_shared_diagnostics(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        $this->post('/admin/targets/preflight', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'ssh-blocked',
            'display_name' => 'Blocked SSH',
            'ssh_host' => '127.0.0.1',
            'ssh_port' => 22,
            'ssh_private_key' => 'NEVER_FLASH_THIS_PRIVATE_KEY',
        ])->assertRedirect('/admin/targets/create?connector_type=ssh_direct');

        $result = session('target_endpoint_preflight');
        self::assertIsArray($result);
        self::assertFalse($result['ok']);
        self::assertStringContainsString('127.0.0.1', $result['message']);
        self::assertStringContainsString('SSRF', $result['next_step']);
        self::assertTrue(Str::isUuid($result['reference']));
        self::assertArrayNotHasKey('ssh_private_key', session()->getOldInput());

        $this->get('/admin/targets/create?connector_type=ssh_direct')
            ->assertOk()->assertSee('127.0.0.1')->assertSee('What to check');
        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
    }

    public function test_preflight_and_registration_never_replay_signed_or_credential_bearing_url_input(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        foreach (['/admin/targets/preflight', '/admin/targets'] as $path) {
            $response = $this->post($path, [
                'connector_type' => 'wp_ai_bridge',
                'target_id' => 'url-secret-check',
                'display_name' => 'Do not flash URLs',
                'base_url' => 'https://user:SECRET_PASSWORD@wordpress.example.test/?token=SECRET_TOKEN',
            ]);
            if ($path === '/admin/targets/preflight') {
                $response->assertSessionHas('target_endpoint_preflight');
                self::assertFalse(session('target_endpoint_preflight')['ok']);
            } else {
                $response->assertSessionHasErrors('base_url');
            }
            self::assertArrayNotHasKey('base_url', session()->getOldInput());
            $this->get('/admin/targets/create?connector_type=wp_ai_bridge')
                ->assertOk()->assertDontSee('SECRET_PASSWORD')->assertDontSee('SECRET_TOKEN');
        }

        Http::assertNothingSent();
        self::assertSame(0, Target::query()->count());
    }

    public function test_registration_uses_only_the_selected_connector_schema_and_does_not_flash_ssh_secrets(): void
    {
        $this->actingAs($this->user('owner', 'all'));

        $this->post('/admin/targets', [
            'connector_type' => 'ssh_direct',
            'target_id' => 'ssh-secret-guard',
            'display_name' => 'SSH secret guard',
            'ssh_auth_method' => 'private_key',
            'ssh_private_key' => 'SECRET_PRIVATE_KEY_SHOULD_NOT_ENTER_SESSION',
            'ssh_passphrase' => 'SECRET_PASSPHRASE_SHOULD_NOT_ENTER_SESSION',
            'ssh_password' => 'SECRET_PASSWORD_SHOULD_NOT_ENTER_SESSION',
            'future_api_token' => 'SECRET_UNKNOWN_CONNECTOR_TOKEN',
            'ssh_trust_confirmed' => 'yes',
        ])->assertSessionHasErrors('ssh_host');

        $old = session()->getOldInput();
        foreach (['ssh_private_key', 'ssh_passphrase', 'ssh_password', 'future_api_token'] as $secret) {
            self::assertArrayNotHasKey($secret, $old);
        }

        // An explicitly unsupported connector type cannot use the common router.
        $this->post('/admin/targets', [
            'connector_type' => 'ai_server_agent',
            'target_id' => 'unsupported-agent',
            'display_name' => 'Unsupported',
        ])->assertSessionHasErrors('connector_type');

        // Irrelevant SSH fields must not make an ordinary WordPress Target invalid.
        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'wp-schema-only',
            'display_name' => 'WordPress schema only',
            'base_url' => 'https://wordpress.example.test/',
            'ssh_auth_method' => 'password',
        ])->assertRedirect('/admin/targets/wp-schema-only');

        self::assertSame(1, Target::query()->count());
        self::assertSame('wp_ai_bridge', Target::query()->firstOrFail()->connector_type);
    }

    public function test_owner_can_edit_label_and_ai_guidance_without_mutating_target_identity_or_connector(): void
    {
        $owner = $this->user('owner', 'all');
        $viewer = $this->user('viewer', 'all');
        $target = $this->target('permanent-id', 'wp_ai_bridge');
        $recordId = (string) $target->getKey();

        $this->actingAs($viewer)->get('/admin/targets/permanent-id/edit')->assertForbidden();
        $this->put('/admin/targets/permanent-id', ['display_name' => 'Unauthorized'])->assertForbidden();

        $this->actingAs($owner)->get('/admin/targets/permanent-id/edit')->assertOk()
            ->assertSee('Stable Target ID')
            ->assertSee('permanent-id');
        $this->put('/admin/targets/permanent-id', [
            'display_name' => 'Updated safe label',
            'ai_guidance' => 'Test production note
A second line.',
            'target_id' => 'hijack',
            'connector_type' => 'ssh_direct',
            'base_url' => 'https://attacker.example.test',
        ])->assertRedirect('/admin/targets/permanent-id');

        $target->refresh();
        self::assertSame($recordId, (string) $target->getKey());
        self::assertSame('permanent-id', $target->target_id);
        self::assertSame('wp_ai_bridge', $target->connector_type);
        self::assertSame('Updated safe label', $target->display_name);
        self::assertSame('Test production note
A second line.', $target->ai_guidance);
        $this->get('/admin/targets/permanent-id')->assertOk()
            ->assertSee('Test production note')
            ->assertSee('Edit Target');
        $this->put('/admin/targets/permanent-id', ['display_name' => 'Keep guidance'])
            ->assertRedirect('/admin/targets/permanent-id');
        self::assertSame('Test production note
A second line.', $target->refresh()->ai_guidance);
        $this->put('/admin/targets/permanent-id', [
            'display_name' => 'Clear guidance',
            'ai_guidance' => '',
        ])->assertRedirect('/admin/targets/permanent-id');
        self::assertNull($target->refresh()->ai_guidance);
    }

    public function test_ai_guidance_validation_rejects_oversize_and_control_bytes_without_registration(): void
    {
        $this->actingAs($this->user('owner', 'all'));
        $fields = [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'guidance-limits',
            'display_name' => 'Bounded guidance',
            'base_url' => 'https://wordpress.example.test/',
            'ai_guidance' => str_repeat('a', Target::AI_GUIDANCE_MAX_LENGTH + 1),
        ];
        $this->post('/admin/targets', $fields)->assertSessionHasErrors('ai_guidance');
        self::assertSame(0, Target::query()->count());

        $fields['ai_guidance'] = 'Production noteforbidden-control';
        $this->post('/admin/targets', $fields)->assertSessionHasErrors('ai_guidance');
        self::assertSame(0, Target::query()->count());

        $fields['ai_guidance'] = '  Sensitive <script>alert(1)</script> note  ';
        $this->post('/admin/targets', $fields)->assertRedirect('/admin/targets/guidance-limits');
        $target = Target::query()->where('target_id', 'guidance-limits')->sole();
        self::assertSame('Sensitive <script>alert(1)</script> note', $target->ai_guidance);
        $this->get('/admin/targets/guidance-limits')->assertOk()
            ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', false)
            ->assertDontSee('<script>alert(1)</script>', false);

        $this->put('/admin/targets/guidance-limits', [
            'display_name' => 'Bounded guidance',
            'ai_guidance' => str_repeat('a', Target::AI_GUIDANCE_MAX_LENGTH + 1),
        ])->assertSessionHasErrors('ai_guidance');
        self::assertSame('Sensitive <script>alert(1)</script> note', $target->refresh()->ai_guidance);
    }

    public function test_remove_requires_confirmation_and_refuses_active_or_pending_connection_state(): void
    {
        $owner = $this->user('owner', 'all');
        $viewer = $this->user('viewer', 'all');
        $target = $this->target('to-remove', 'wp_ai_bridge');
        DB::table('user_target_access')->insert([
            'user_id' => $viewer->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);

        $this->actingAs($viewer)->delete('/admin/targets/to-remove', ['confirm_remove' => 'yes'])->assertForbidden();
        $this->actingAs($owner)->delete('/admin/targets/to-remove')->assertSessionHasErrors('confirm_remove');
        self::assertSame(1, Target::query()->where('target_id', 'to-remove')->count());

        $target->forceFill(['connection_state' => 'connected'])->save();
        $this->delete('/admin/targets/to-remove', ['confirm_remove' => 'yes'])->assertSessionHasErrors('target');
        self::assertSame(1, Target::query()->where('target_id', 'to-remove')->count());
        $target->forceFill(['connection_state' => 'disconnected'])->save();

        $this->delete('/admin/targets/to-remove', ['confirm_remove' => 'yes'])
            ->assertRedirect('/admin/targets');
        self::assertSame(0, Target::query()->where('target_id', 'to-remove')->count());
        self::assertSame(0, DB::table('user_target_access')
            ->where('target_record_id', $target->getKey())->count());
        self::assertSame(1, DB::table('activity_events')
            ->where('target_id', 'to-remove')->where('operation', 'target-remove')->count());
        $this->get('/admin/sites')->assertNotFound();
        $this->get('/admin/site-checks')->assertNotFound();
    }

    #[Group('database-access')]
    public function test_owner_can_forget_network_failed_wordpress_with_pending_oauth_and_preserve_audit_without_remote_io(): void
    {
        $owner = $this->user('owner', 'all');
        $viewer = $this->user('viewer', 'selected');
        $target = $this->target('unreachable-wp', 'wp_ai_bridge');
        $target->forceFill([
            'connection_state' => 'error',
            'last_error_code' => 'network_failure',
        ])->save();
        $recordId = (string) $target->getKey();
        $credential = TargetCredential::query()->create([
            'target_record_id' => $recordId,
            'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth',
            'encrypted_payload' => 'unopened-test-fixture',
        ]);
        $now = now();
        DB::table('wp_ai_bridge_target_configs')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $recordId,
            'base_url' => 'https://wordpress.example.test',
            'base_url_hash' => hash('sha256', 'https://wordpress.example.test'),
            'mcp_resource_url' => 'https://wordpress.example.test/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => 'https://wordpress.example.test',
            'oauth_authorization_url' => 'https://wordpress.example.test/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => 'https://wordpress.example.test/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => 'https://wordpress.example.test/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('wp_ai_bridge_credential_metadata')->insert([
            'credential_id' => $credential->getKey(),
            'client_id' => 'test-gateway',
            'resource_url' => 'https://wordpress.example.test/wp-json/wp-ai-bridge/v1/mcp',
            'binding_hash' => hash('sha256', 'bound-credential'),
            'generation' => 1,
        ]);
        DB::table('wp_ai_bridge_refresh_intents')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $recordId,
            'credential_id' => $credential->getKey(),
            'generation' => 1,
            'attempts' => 2,
            'request_timeout_seconds' => 9,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('wp_ai_bridge_revocation_intents')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $recordId,
            'kind' => 'disconnect',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('wp_ai_bridge_oauth_flows')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $recordId,
            'state_hash' => hash('sha256', 'unconsumed-test-flow'),
            'encrypted_context' => 'opaque-test-context',
            'expires_at' => now()->addMinutes(10),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('user_target_access')->insert([
            'user_id' => $viewer->getKey(),
            'target_record_id' => $recordId,
            'allowed' => true,
        ]);
        DB::table('user_target_permission_denials')->insert([
            'user_id' => $viewer->getKey(),
            'target_record_id' => $recordId,
            'permission' => 'wordpress.abilities.execute.mutating',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $groupId = (string) Str::ulid();
        DB::table('target_groups')->insert([
            'id' => $groupId,
            'name' => 'Forget test group',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('target_group_targets')->insert([
            'target_group_id' => $groupId,
            'target_record_id' => $recordId,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $operationId = (string) Str::uuid();
        DB::table('target_check_operations')->insert([
            'id' => $operationId,
            'creator_user_id' => $owner->getKey(),
            'idempotency_key' => (string) Str::uuid(),
            'status' => 'complete',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('target_check_operation_targets')->insert([
            'id' => (string) Str::ulid(),
            'operation_id' => $operationId,
            'target_record_id' => $recordId,
            'target_id_snapshot' => $target->target_id,
            'display_name_snapshot' => $target->display_name,
            'position' => 1,
            'status' => 'complete',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $this->actingAs($owner);
        $this->get('/admin/targets/unreachable-wp')->assertOk()
            ->assertSee('Permanently remove Target locally')
            ->assertSee('without remote revocation');
        $this->delete('/admin/targets/unreachable-wp', ['confirm_remove' => 'yes'])
            ->assertSessionHasErrors('target');
        self::assertSame(1, Target::query()->whereKey($recordId)->count());

        $this->delete('/admin/targets/unreachable-wp/forget', [
            'confirm_target_id' => 'unreachable-wp',
            'confirm_local_only' => 'yes',
            'confirm_remote_revocation_unknown' => 'yes',
            'current_password' => 'ThisIsATestSecret!234',
        ])->assertRedirect('/admin/targets')->assertSessionHas('status');

        self::assertSame(0, Target::query()->whereKey($recordId)->count());
        foreach ([
            'target_credentials',
            'wp_ai_bridge_credential_metadata',
            'wp_ai_bridge_target_configs',
            'wp_ai_bridge_refresh_intents',
            'wp_ai_bridge_revocation_intents',
            'wp_ai_bridge_oauth_flows',
            'user_target_access',
            'user_target_permission_denials',
            'target_group_targets',
        ] as $table) {
            $column = $table === 'wp_ai_bridge_credential_metadata' ? 'credential_id' : 'target_record_id';
            $lookup = $table === 'wp_ai_bridge_credential_metadata' ? $credential->getKey() : $recordId;
            self::assertSame(0, DB::table($table)->where($column, $lookup)->count(), $table);
        }
        $snapshot = DB::table('target_check_operation_targets')
            ->where('operation_id', $operationId)->first();
        self::assertNotNull($snapshot);
        self::assertNull($snapshot->target_record_id);
        self::assertSame('unreachable-wp', $snapshot->target_id_snapshot);

        $audit = DB::table('activity_events')
            ->where('target_id', 'unreachable-wp')->where('operation', 'target-forget-local')->sole();
        self::assertSame($recordId, $audit->target_record_id);
        self::assertSame('wp_ai_bridge', $audit->connector_type_snapshot);
        self::assertSame('success', $audit->outcome);
        self::assertSame('remote_revocation_unverified', $audit->error_code);
        Http::assertNothingSent();

        // Reusing the human Target ID creates a different database identity.
        // Deleted ACLs, OAuth intents and credentials must never carry over.
        $replacement = $this->target('unreachable-wp', 'wp_ai_bridge');
        self::assertNotSame($recordId, (string) $replacement->getKey());
        self::assertSame(0, DB::table('user_target_access')
            ->where('target_record_id', $replacement->getKey())->count());
        self::assertSame(0, DB::table('target_credentials')
            ->where('target_record_id', $replacement->getKey())->count());
        $this->actingAs($viewer)->get('/admin/targets/unreachable-wp')->assertForbidden();
    }

    public function test_offline_removal_is_owner_only_and_requires_exact_id_password_and_both_acknowledgments(): void
    {
        $target = $this->target('offline-protected', 'wp_ai_bridge');
        $target->forceFill(['connection_state' => 'connected'])->save();
        $input = [
            'confirm_target_id' => 'offline-protected',
            'confirm_local_only' => 'yes',
            'confirm_remote_revocation_unknown' => 'yes',
            'current_password' => 'ThisIsATestSecret!234',
        ];
        $path = '/admin/targets/offline-protected/forget';
        $this->actingAs($this->user('administrator', 'all'));
        $this->get('/admin/targets/offline-protected')->assertOk()
            ->assertDontSee('Permanently remove Target locally');
        $this->delete($path, $input)->assertForbidden();
        $this->actingAs($this->user('viewer', 'all'))
            ->delete($path, $input)->assertForbidden();
        $this->actingAs($this->user('owner', 'all'));
        $this->delete($path)->assertSessionHasErrors([
            'confirm_target_id',
            'confirm_local_only',
            'confirm_remote_revocation_unknown',
        ]);
        $this->delete($path, [...$input, 'confirm_target_id' => 'another-target'])
            ->assertSessionHasErrors('confirm_target_id');
        $this->delete($path, [...$input, 'current_password' => 'invalid-owner-password'])
            ->assertSessionHasErrors('current_password');
        $this->delete($path, [...$input, 'confirm_remote_revocation_unknown' => 'no'])
            ->assertSessionHasErrors('confirm_remote_revocation_unknown');
        self::assertSame(1, Target::query()->whereKey($target->getKey())->count());
        self::assertSame(0, DB::table('activity_events')
            ->where('target_id', 'offline-protected')->where('operation', 'target-forget-local')->count());
        Http::assertNothingSent();
    }

    #[Group('database-access')]
    public function test_offline_removal_also_forgets_ssh_credential_and_paused_connector_without_remote_network(): void
    {
        $owner = $this->user('owner', 'all');
        $this->actingAs($owner);
        $ssh = $this->target('offline-ssh', 'ssh_direct');
        $ssh->forceFill(['connection_state' => 'connected'])->save();
        $recordId = (string) $ssh->getKey();
        TargetCredential::query()->create([
            'target_record_id' => $recordId,
            'connector_type' => 'ssh_direct',
            'purpose' => 'ssh_login',
            'encrypted_payload' => 'unopened-ssh-test-fixture',
        ]);
        DB::table('ssh_direct_target_configs')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $recordId,
            'host' => '198.51.100.20',
            'port' => 22,
            'username' => 'ssh-test',
            'auth_method' => 'password',
            'pinned_host_key' => 'test-only-key',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $input = [
            'confirm_target_id' => 'offline-ssh',
            'confirm_local_only' => 'yes',
            'confirm_remote_revocation_unknown' => 'yes',
            'current_password' => 'ThisIsATestSecret!234',
        ];
        $this->delete('/admin/targets/offline-ssh/forget', $input)->assertRedirect('/admin/targets');
        self::assertSame(0, Target::query()->whereKey($recordId)->count());
        self::assertSame(0, DB::table('target_credentials')
            ->where('target_record_id', $recordId)->count());
        self::assertSame(0, DB::table('ssh_direct_target_configs')
            ->where('target_record_id', $recordId)->count());

        $paused = $this->target('offline-paused', 'wp_ai_bridge');
        $paused->forceFill(['connection_state' => 'error'])->save();
        $this->delete('/admin/targets/offline-paused/forget', [
            ...$input,
            'confirm_target_id' => 'offline-paused',
        ])->assertRedirect('/admin/targets');
        self::assertSame(0, Target::query()->whereKey($paused->getKey())->count());
        self::assertSame(2, DB::table('activity_events')
            ->where('operation', 'target-forget-local')->count());
        Http::assertNothingSent();
    }

    public function test_local_forget_rolls_back_audit_and_credentials_when_database_delete_fails(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite') {
            $this->markTestSkipped('SQLite fixture injects a deterministic Target delete failure.');
        }

        $target = $this->target('rollback-forget', 'wp_ai_bridge');
        $target->forceFill(['connection_state' => 'error'])->save();
        $id = (string) $target->getKey();
        TargetCredential::query()->create([
            'target_record_id' => $id,
            'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth',
            'encrypted_payload' => 'unopened-failure-fixture',
        ]);

        DB::statement("CREATE TRIGGER fail_target_local_forget BEFORE DELETE ON targets BEGIN SELECT RAISE(ABORT, 'forced_delete_failure'); END");
        try {
            $this->actingAs($this->user('owner', 'all'))
                ->delete('/admin/targets/rollback-forget/forget', [
                    'confirm_target_id' => 'rollback-forget',
                    'confirm_local_only' => 'yes',
                    'confirm_remote_revocation_unknown' => 'yes',
                    'current_password' => 'ThisIsATestSecret!234',
                ])->assertStatus(500);
        } finally {
            DB::statement('DROP TRIGGER IF EXISTS fail_target_local_forget');
        }

        self::assertSame(1, Target::query()->whereKey($id)->count());
        self::assertSame(1, DB::table('target_credentials')
            ->where('target_record_id', $id)->count());
        self::assertSame(0, DB::table('activity_events')
            ->where('target_id', 'rollback-forget')->where('operation', 'target-forget-local')->count());
        Http::assertNothingSent();
    }

    public function test_target_admin_lifecycle_routes_remain_authenticated_and_web_csrf_guarded(): void
    {
        foreach (['/admin/targets', '/admin/targets/create', '/admin/activity'] as $path) {
            $this->get($path)->assertRedirect('/admin/login');
        }

        foreach ([
            'admin.targets.store',
            'admin.targets.update',
            'admin.targets.destroy',
            'admin.targets.forget',
            'admin.targets.connect',
            'admin.targets.reconnect',
            'admin.targets.disconnect',
            'admin.targets.test',
        ] as $name) {
            $route = Route::getRoutes()->getByName($name);
            self::assertNotNull($route, $name);
            self::assertContains('web', $route->middleware(), $name);
            self::assertContains('auth', $route->middleware(), $name);
        }

        foreach (['admin.sites.store', 'admin.site-checks.store', 'bridge.site.callback'] as $old) {
            self::assertNull(Route::getRoutes()->getByName($old), $old);
        }
    }

    public function test_target_explicit_metadata_check_stores_bounded_failure_without_network_on_read(): void
    {
        $owner = $this->user('owner', 'all');
        $this->actingAs($owner);
        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'metadata-fail',
            'display_name' => 'Metadata check',
            'base_url' => 'https://wordpress.example.test/',
        ])->assertRedirect('/admin/targets/metadata-fail');

        $target = Target::query()->where('target_id', 'metadata-fail')->sole();
        Http::assertSentCount(2);
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(static fn (Request $request) => Http::response(['error' => 'not_found'], 404));

        $this->get('/admin/targets/'.$target->target_id)->assertOk();
        Http::assertNothingSent();

        $failure = $this->post(route('admin.targets.test', ['target' => $target->target_id], false))
            ->assertRedirect('/admin/targets/'.$target->target_id)
            ->assertSessionHasErrors('target')
            ->assertSessionHas('diagnostic_code', 'missing_bridge');
        self::assertTrue(Str::isUuid((string) session('diagnostic_reference')));
        $failure->assertHeader('X-Correlation-ID', (string) session('diagnostic_reference'));
        $target->refresh();
        self::assertNotNull($target->last_tested_at);
        self::assertSame('missing_bridge', $target->last_error_code);
        self::assertSame('missing_bridge', $target->last_failure_code);
        self::assertNotNull($target->last_failure_at);
        $this->get('/admin/targets/'.$target->target_id)
            ->assertOk()->assertSee('missing_bridge');
    }

    private function user(string $role, string $scope): User
    {
        return User::query()->create([
            'name' => 'Test '.$role,
            'email' => uniqid('account-', true).'@example.test',
            'password' => 'ThisIsATestSecret!234',
            'role' => $role,
            'target_scope_mode' => $scope,
            'access_enabled' => true,
        ]);
    }

    private function target(string $id, string $connector, ?string $name = null): Target
    {
        return Target::query()->create([
            'target_id' => $id,
            'display_name' => $name ?? 'Target '.$id,
            'connector_type' => $connector,
        ]);
    }

    private function metadata(Request $request): PromiseInterface
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
            ]);
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
            ]);
        }

        return Http::response([], 404);
    }
}
