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
            public function resolve(string $host): array
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
