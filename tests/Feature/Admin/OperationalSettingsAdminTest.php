<?php

namespace Tests\Feature\Admin;

use App\Application\Operations\OperationalSettings;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

final class OperationalSettingsAdminTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return ['1.1.1.1'];
            }
        });
        Http::preventStrayRequests();
    }

    public function test_guest_and_nonowner_cannot_view_or_change_gateway_operational_settings(): void
    {
        $this->get('/admin/operations')->assertRedirect('/admin/login');

        foreach (['administrator', 'operator', 'viewer'] as $role) {
            $this->actingAs($this->account($role))
                ->get('/admin/operations')
                ->assertForbidden();
            $this->put('/admin/operations', [
                'version' => '0',
                'values' => ['wp_response_kib' => '256', 'wp_readonly_response_kib' => '512'],
                'current_password' => 'CorrectHorse!234',
            ])->assertForbidden();
        }
        self::assertSame(0, DB::table('operational_settings')->where('id', 1)->value('version'));
        self::assertSame(0, DB::table('operational_setting_changes')->count());
    }

    public function test_operator_settings_form_is_grouped_but_preserves_every_audited_allowlist_input(): void
    {
        $this->actingAs($this->account('owner'));
        $html = $this->get('/admin/operations')->assertOk()
            ->assertSee('WordPress responses')
            ->assertSee('WordPress connection deadlines')
            ->assertSee('SSH whole-file transfer')
            ->assertSee('Detached SSH Jobs')
            ->assertSee('Outbound DNS compatibility preflight')
            ->assertSee('/etc/resolv.conf')
            ->assertSee('/etc/hosts')
            ->assertSee('Use default')
            ->assertSee('Settings revision')
            ->getContent();
        $dom = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $xpath = new \DOMXPath($dom);
        self::assertSame(1, (int) $xpath->evaluate('count(//form[contains(@class,"operations-form")])'));
        self::assertSame(5, (int) $xpath->evaluate('count(//fieldset[contains(@class,"operations-group") and not(contains(@class,"operations-confirmation"))])'));
        self::assertSame(13, (int) $xpath->evaluate('count(//div[contains(@class,"operations-setting") and contains(@class,"field")])'));
        self::assertSame(13, (int) $xpath->evaluate('count(//input[@type="number"][starts-with(@name,"values[")])'));
        self::assertSame(13, (int) $xpath->evaluate('count(//button[@data-clear-setting])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//input[@type="password"][@name="current_password"][@required])'));
        self::assertSame(1, (int) $xpath->evaluate('count(//input[@type="hidden"][@name="version"])'));
        foreach (array_keys(OperationalSettings::allowed()) as $key) {
            self::assertSame(1, (int) $xpath->evaluate('count(//input[@name="values['.$key.']"])'));
        }
    }

    public function test_owner_can_set_both_finite_response_budgets_and_reset_them_without_redeploy(): void
    {
        config()->set('bridge.http.max_response_bytes', 65537);
        config()->set('bridge.http.readonly_tool_max_response_bytes', 262144);
        $owner = $this->account('owner');
        $this->actingAs($owner)->get('/admin/operations')
            ->assertOk()
            ->assertSee('Operational settings')
            ->assertSee('Owner password')
            ->assertSee('Current effective')
            ->assertSee('Leave empty to restore the default');

        $settings = app(OperationalSettings::class);
        self::assertSame(65537, $settings->responseLimitBytes(false));
        self::assertSame(262144, $settings->responseLimitBytes(true));

        $this->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '192', 'wp_readonly_response_kib' => '512'],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect(route('admin.operations.index'));

        self::assertSame(192 * 1024, (new OperationalSettings)->responseLimitBytes(false));
        self::assertSame(512 * 1024, (new OperationalSettings)->responseLimitBytes(true));
        self::assertSame(1, (int) DB::table('operational_settings')->value('version'));
        self::assertSame(2, DB::table('operational_setting_changes')->count());
        self::assertEqualsCanonicalizing(
            ['wp_response_kib', 'wp_readonly_response_kib'],
            DB::table('operational_setting_changes')->pluck('setting_key')->all(),
        );
        self::assertSame(1, (int) DB::table('operational_setting_changes')
            ->where('actor_user_id', $owner->getKey())->distinct()->count('actor_user_id'));
        self::assertSame(null, DB::table('operational_setting_changes')->value('previous_value'));

        // A different consumer/process (e.g. the next PHP-FPM request or
        // a new Artisan maintenance invocation) reads the same persisted
        // override; no stale env rewrite or global mutable singleton.
        $fresh = new OperationalSettings;
        self::assertSame(192 * 1024, $fresh->responseLimitBytes(false));
        self::assertSame(512 * 1024, $fresh->responseLimitBytes(true));

        $this->put('/admin/operations', [
            'version' => '1',
            'values' => ['wp_response_kib' => '', 'wp_readonly_response_kib' => ''],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect(route('admin.operations.index'));

        self::assertSame(65537, (new OperationalSettings)->responseLimitBytes(false));
        self::assertSame(262144, (new OperationalSettings)->responseLimitBytes(true));
        self::assertSame(2, (int) DB::table('operational_settings')->value('version'));
        self::assertSame(4, DB::table('operational_setting_changes')->count());
        self::assertSame(2, DB::table('operational_setting_changes')->whereNull('new_value')->count());
    }

    public function test_validated_owner_settings_apply_to_real_outbound_http_but_hard_limit_and_classification_remain_separate(): void
    {
        $owner = $this->account('owner');
        $this->actingAs($owner)->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '192', 'wp_readonly_response_kib' => '512'],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $body = str_repeat('a', 130 * 1024);
        Http::fake(fn (Request $request) => Http::response($body, 200));

        // Ordinary responses now permit 130 KiB (previously only 64 KiB).
        $client = app(SafeHttpClient::class);
        self::assertSame($body, $client->get('https://wp.example.test/metadata')->body);

        // 192 KiB ordinary budget still denies 200 KiB; a wider read-only
        // budget must be selected only explicitly by the trusted caller.
        $larger = str_repeat('b', 200 * 1024);
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(fn (Request $request) => Http::response($larger, 200));
        try {
            $client->get('https://wp.example.test/metadata');
            self::fail('Ordinary response bypassed the smaller operator budget.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('response_too_large', $exception->reason);
            self::assertSame(192 * 1024, $exception->details['limit_bytes']);
        }
        self::assertSame($larger, $client->postJson('https://wp.example.test/wp-json/wp-ai-bridge/v1/mcp', [], [], 512 * 1024)->body);
    }

    public function test_invalid_and_stale_edits_fail_without_new_audit_or_loss_of_override(): void
    {
        $owner = $this->account('owner');
        $this->actingAs($owner)->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '1025', 'wp_readonly_response_kib' => '512'],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('values.wp_response_kib');
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '128', 'wp_readonly_response_kib' => '9999999'],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('values.wp_readonly_response_kib');
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '128', 'wp_readonly_response_kib' => '512', 'secret' => 'attack'],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('values');
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '128', 'wp_readonly_response_kib' => '512'],
            'current_password' => 'incorrect',
        ])->assertSessionHasErrors('current_password');

        self::assertSame(0, DB::table('operational_setting_changes')->count());
        self::assertSame(0, (int) DB::table('operational_settings')->value('version'));

        $this->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '128', 'wp_readonly_response_kib' => '512'],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => ['wp_response_kib' => '256', 'wp_readonly_response_kib' => '512'],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('version');
        self::assertSame(128 * 1024, (new OperationalSettings)->responseLimitBytes(false));
        self::assertSame(2, DB::table('operational_setting_changes')->count());
        self::assertSame(1, (int) DB::table('operational_settings')->value('version'));
    }

    public function test_owner_can_tune_connection_and_total_request_deadlines_without_env_edit_and_legacy_form_preserves_them(): void
    {
        config()->set('bridge.http.connect_timeout_seconds', 2);
        config()->set('bridge.http.request_timeout_seconds', 5);
        $owner = $this->account('owner');
        $this->actingAs($owner)->get('/admin/operations')
            ->assertOk()
            ->assertSee('WordPress connection deadlines')
            ->assertSee('Total request deadline')
            ->assertSee('wp_connect_timeout_seconds')
            ->assertSee('wp_request_timeout_seconds');

        self::assertSame(['connect' => 2, 'request' => 5],
            (new OperationalSettings)->httpTimeoutsSeconds());

        $this->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '6',
                'wp_request_timeout_seconds' => '18',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect(route('admin.operations.index'));

        self::assertSame(['connect' => 6, 'request' => 18],
            (new OperationalSettings)->httpTimeoutsSeconds());
        self::assertSame(1, (int) DB::table('operational_settings')->value('version'));
        self::assertEqualsCanonicalizing(
            ['wp_connect_timeout_seconds', 'wp_request_timeout_seconds'],
            DB::table('operational_setting_changes')->pluck('setting_key')->all(),
        );
        // Older app releases decode this JSON and reject unknown keys.
        // Timeout columns are deliberately separated for safe source rollback.
        $row = DB::table('operational_settings')->first();
        self::assertSame([], json_decode((string) $row->overrides, true));
        self::assertSame(6, (int) $row->wp_connect_timeout_seconds);
        self::assertSame(18, (int) $row->wp_request_timeout_seconds);
        // An older Owner tab still posts only the original two response keys.
        // Its save must not discard already persisted new timeout overrides.
        $this->put('/admin/operations', [
            'version' => '1',
            'values' => ['wp_response_kib' => '128', 'wp_readonly_response_kib' => ''],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['connect' => 6, 'request' => 18],
            (new OperationalSettings)->httpTimeoutsSeconds());
        self::assertSame(128 * 1024, (new OperationalSettings)->responseLimitBytes(false));
        self::assertSame(2, (int) DB::table('operational_settings')->value('version'));

        $this->put('/admin/operations', [
            'version' => '2',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['connect' => 2, 'request' => 5],
            (new OperationalSettings)->httpTimeoutsSeconds());
        self::assertSame([], (new OperationalSettings)->state()['overrides']);
        self::assertSame(3, (int) DB::table('operational_settings')->value('version'));
        self::assertSame(6, DB::table('operational_setting_changes')->count());
    }

    public function test_invalid_timeout_pairs_stale_version_and_unknown_fields_do_not_mutate_or_audit(): void
    {
        $owner = $this->account('owner');
        $this->actingAs($owner);

        foreach ([
            ['wp_connect_timeout_seconds' => '15', 'wp_request_timeout_seconds' => '14'],
            ['wp_connect_timeout_seconds' => '16', 'wp_request_timeout_seconds' => '30'],
            ['wp_connect_timeout_seconds' => '1', 'wp_request_timeout_seconds' => '31'],
        ] as $invalid) {
            $this->put('/admin/operations', [
                'version' => '0',
                'values' => [
                    'wp_response_kib' => '',
                    'wp_readonly_response_kib' => '',
                    ...$invalid,
                ],
                'current_password' => 'CorrectHorse!234',
            ])->assertSessionHasErrors();
        }
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '3',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('values');
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '4',
                'wp_request_timeout_seconds' => '12',
                'hidden_switch' => 'anything',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('values');

        self::assertSame(0, (int) DB::table('operational_settings')->value('version'));
        self::assertSame(0, DB::table('operational_setting_changes')->count());
        $this->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '4',
                'wp_request_timeout_seconds' => '12',
            ],
            'current_password' => 'incorrect',
        ])->assertSessionHasErrors('current_password');
        self::assertSame(0, DB::table('operational_setting_changes')->count());
    }

    public function test_legacy_env_timeout_normalization_does_not_block_unrelated_owner_response_budget_edits(): void
    {
        // The pre-existing safe HTTP transport accepted this source pair by
        // using max(connect, request) as its total deadline. A response-only
        // Owner change must not newly brick the form on such installations.
        config()->set('bridge.http.connect_timeout_seconds', 12);
        config()->set('bridge.http.request_timeout_seconds', 5);
        self::assertSame(['connect' => 12, 'request' => 12],
            (new OperationalSettings)->httpTimeoutsSeconds());

        $owner = $this->account('owner');
        $this->actingAs($owner)->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '128',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect(route('admin.operations.index'));
        self::assertSame(128 * 1024, (new OperationalSettings)->responseLimitBytes(false));
        self::assertSame(['connect' => 12, 'request' => 12],
            (new OperationalSettings)->httpTimeoutsSeconds());
        self::assertSame(1, DB::table('operational_settings')->value('version'));

        // Explicitly unsafe new pairs are still blocked; no audit change.
        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '128',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '10',
                'wp_request_timeout_seconds' => '5',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors('values.wp_request_timeout_seconds');
        self::assertSame(1, DB::table('operational_settings')->value('version'));
        self::assertSame(1, DB::table('operational_setting_changes')->count());
    }

    public function test_persisted_two_second_total_deadline_includes_dns_and_new_request_sees_reset(): void
    {
        config()->set('bridge.http.connect_timeout_seconds', 2);
        config()->set('bridge.http.request_timeout_seconds', 5);
        $owner = $this->account('owner');
        $this->actingAs($owner)->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '1',
                'wp_request_timeout_seconds' => '2',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();

        $resolver = new class implements DnsResolver
        {
            public int $queries = 0;

            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                $this->queries++;
                usleep(2_200_000);

                return ['1.1.1.1'];
            }
        };
        $this->app->instance(DnsResolver::class, $resolver);
        Http::fake(fn (Request $request) => Http::response('ready', 200));
        try {
            app(SafeHttpClient::class)->get('https://wp.example.test/metadata');
            self::fail('A two-second total network deadline must include the DNS time.');
        } catch (OutboundRequestException $exception) {
            self::assertSame('network_failure', $exception->reason);
        }
        Http::assertNothingSent();
        self::assertSame(1, $resolver->queries);
        self::assertSame(['connect' => 1, 'request' => 2],
            (new OperationalSettings)->httpTimeoutsSeconds());

        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame('ready', app(SafeHttpClient::class)
            ->get('https://wp.example.test/metadata')->body);
        Http::assertSentCount(1);
        self::assertSame(2, $resolver->queries);
    }

    public function test_owner_can_tune_ssh_file_transfer_budgets_without_creating_a_second_settings_service(): void
    {
        config()->set('ssh.file_transfer.max_bytes', 8388608);
        config()->set('ssh.file_transfer.max_seconds', 30);
        $owner = $this->account('owner');
        $this->actingAs($owner);
        $settings = app(OperationalSettings::class);
        self::assertSame(['max_bytes' => 8388608, 'max_seconds' => 30], $settings->sshTransferLimits());

        $this->get('/admin/operations')->assertOk()
            ->assertSee('SSH whole-file transfer')
            ->assertSee('ssh_transfer_max_kib')
            ->assertSee('ssh_transfer_max_seconds');

        $this->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
                'ssh_transfer_max_kib' => '2048',
                'ssh_transfer_max_seconds' => '20',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['max_bytes' => 2097152, 'max_seconds' => 20],
            (new OperationalSettings)->sshTransferLimits());
        $row = DB::table('operational_settings')->first();
        self::assertSame(2048, (int) $row->ssh_transfer_max_kib);
        self::assertSame(20, (int) $row->ssh_transfer_max_seconds);
        self::assertSame([], json_decode((string) $row->overrides, true));
        self::assertEqualsCanonicalizing(
            ['ssh_transfer_max_kib', 'ssh_transfer_max_seconds'],
            DB::table('operational_setting_changes')->pluck('setting_key')->all(),
        );

        // Previous four-key admin tab must preserve the newer SSH limits.
        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['max_bytes' => 2097152, 'max_seconds' => 20],
            (new OperationalSettings)->sshTransferLimits());

        // Invalid maximum or deadline never alters a persisted configuration.
        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
                'ssh_transfer_max_kib' => '65537',
                'ssh_transfer_max_seconds' => '0',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors(['values.ssh_transfer_max_kib', 'values.ssh_transfer_max_seconds']);
        self::assertSame(1, (int) DB::table('operational_settings')->value('version'));

        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
                'ssh_transfer_max_kib' => '',
                'ssh_transfer_max_seconds' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['max_bytes' => 8388608, 'max_seconds' => 30],
            (new OperationalSettings)->sshTransferLimits());
        self::assertSame(2, (int) DB::table('operational_settings')->value('version'));
    }

    public function test_ssh_command_budgets_preserve_defaults_and_previous_admin_forms(): void
    {
        $owner = $this->account('owner');
        $this->actingAs($owner);
        self::assertSame(['max_bytes' => 8192, 'max_seconds' => 15],
            (new OperationalSettings)->sshCommandLimits());
        $this->get('/admin/operations')->assertOk()
            ->assertSee('SSH commands')
            ->assertSee('ssh_command_timeout_seconds')
            ->assertSee('ssh_command_max_kib');

        $this->put('/admin/operations', [
            'version' => '0',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
                'ssh_transfer_max_kib' => '',
                'ssh_transfer_max_seconds' => '',
                'ssh_command_timeout_seconds' => '30',
                'ssh_command_max_kib' => '64',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['max_bytes' => 65536, 'max_seconds' => 30],
            (new OperationalSettings)->sshCommandLimits());
        self::assertSame([], json_decode((string) DB::table('operational_settings')->value('overrides'), true));
        self::assertEqualsCanonicalizing(
            ['ssh_command_timeout_seconds', 'ssh_command_max_kib'],
            DB::table('operational_setting_changes')->pluck('setting_key')->all(),
        );

        // A previous six-key UI must not erase new command limits.
        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
                'ssh_transfer_max_kib' => '',
                'ssh_transfer_max_seconds' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['max_bytes' => 65536, 'max_seconds' => 30],
            (new OperationalSettings)->sshCommandLimits());

        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'ssh_command_timeout_seconds' => '31',
                'ssh_command_max_kib' => '65',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors(['values.ssh_command_timeout_seconds', 'values.ssh_command_max_kib']);

        $this->put('/admin/operations', [
            'version' => '1',
            'values' => [
                'wp_response_kib' => '',
                'wp_readonly_response_kib' => '',
                'wp_connect_timeout_seconds' => '',
                'wp_request_timeout_seconds' => '',
                'ssh_transfer_max_kib' => '',
                'ssh_transfer_max_seconds' => '',
                'ssh_command_timeout_seconds' => '',
                'ssh_command_max_kib' => '',
            ],
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame(['max_bytes' => 8192, 'max_seconds' => 15],
            (new OperationalSettings)->sshCommandLimits());
        self::assertSame(2, (int) DB::table('operational_settings')->value('version'));
    }

    public function test_owner_controls_detached_job_budget_and_older_form_preserves_new_settings(): void
    {
        $this->actingAs($this->account('owner'));
        $defaults = [
            'max_active_per_user' => 2, 'max_runtime_seconds' => 300,
            'retention_hours' => 24, 'preparing_grace_seconds' => 120,
            'reconcile_grace_seconds' => 600,
        ];
        self::assertSame($defaults, (new OperationalSettings)->sshJobLimits());

        $blank = array_fill_keys(array_keys(OperationalSettings::allowed()), '');
        $blank['ssh_job_max_active_per_user'] = '25';
        $blank['ssh_job_max_runtime_seconds'] = '86400';
        $blank['ssh_job_retention_hours'] = '168';
        $blank['ssh_job_preparing_grace_seconds'] = '240';
        $blank['ssh_job_reconcile_grace_seconds'] = '1800';
        $this->put('/admin/operations', [
            'version' => '0', 'values' => $blank,
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        $changed = [
            'max_active_per_user' => 25, 'max_runtime_seconds' => 86400,
            'retention_hours' => 168, 'preparing_grace_seconds' => 240,
            'reconcile_grace_seconds' => 1800,
        ];
        self::assertSame($changed, (new OperationalSettings)->sshJobLimits());
        self::assertSame(5, DB::table('operational_setting_changes')->count());

        // An older tab with only eight pre-Job fields must not erase overrides.
        $this->put('/admin/operations', [
            'version' => '1',
            'values' => array_fill_keys(array_slice(array_keys(OperationalSettings::allowed()), 0, 8), ''),
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame($changed, (new OperationalSettings)->sshJobLimits());
        self::assertSame(1, (int) DB::table('operational_settings')->value('version'));

        $wrong = $blank;
        $wrong['ssh_job_max_active_per_user'] = '1025';
        $wrong['ssh_job_max_runtime_seconds'] = '604801';
        $wrong['ssh_job_preparing_grace_seconds'] = '29';
        $this->put('/admin/operations', [
            'version' => '1', 'values' => $wrong,
            'current_password' => 'CorrectHorse!234',
        ])->assertSessionHasErrors([
            'values.ssh_job_max_active_per_user',
            'values.ssh_job_max_runtime_seconds',
            'values.ssh_job_preparing_grace_seconds',
        ]);
        self::assertSame($changed, (new OperationalSettings)->sshJobLimits());

        $this->put('/admin/operations', [
            'version' => '1',
            'values' => array_fill_keys(array_keys(OperationalSettings::allowed()), ''),
            'current_password' => 'CorrectHorse!234',
        ])->assertRedirect();
        self::assertSame($defaults, (new OperationalSettings)->sshJobLimits());
    }

    private function account(string $role): User
    {
        return User::query()->create([
            'name' => 'Settings '.$role,
            'email' => $role.'-settings@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }
}
