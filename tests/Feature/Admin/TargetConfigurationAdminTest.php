<?php

namespace Tests\Feature\Admin;

use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\SshVerificationState;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use phpseclib4\Crypt\EC;
use Tests\TestCase;

final class TargetConfigurationAdminTest extends TestCase
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

    public function test_owner_can_correct_ssh_port_preserve_encrypted_password_and_all_access_assignments(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $this->actingAs($owner);
        $target = $this->ssh();
        $group = TargetGroup::query()->create(['name' => 'Existing users']);
        DB::table('user_target_access')->insert([
            'user_id' => $operator->getKey(),
            'target_record_id' => $target->getKey(),
            'allowed' => true,
        ]);
        DB::table('target_group_targets')->insert([
            'target_group_id' => $group->getKey(),
            'target_record_id' => $target->getKey(),
        ]);
        DB::table('target_group_users')->insert([
            'target_group_id' => $group->getKey(),
            'user_id' => $operator->getKey(),
        ]);
        $oldId = $target->getKey();
        $oldCiphertext = TargetCredential::query()->sole()->encrypted_payload;
        $config = SshTargetConfig::query()->sole();
        $config->forceFill([
            'observed_peer_ip' => '1.1.1.1',
            'observed_at' => now(),
            'verification_attempt_id' => '01K89CB2RVTSPTNYMYZE812QF7',
        ])->save();
        $target->forceFill([
            'connection_state' => TargetConnectionState::Connected,
            'connected_at' => now(),
        ])->save();
        $response = $this->get('/admin/targets/ssh-demo/edit')->assertOk()
            ->assertSee('Current Owner password')
            ->assertSee('SSH host or IP address')
            ->assertDontSee('test-password-secret')
            ->assertDontSee($oldCiphertext);
        $revision = $this->revision($response->getContent());

        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_port' => 2222,
        ]))->assertRedirect('/admin/targets/ssh-demo')->assertSessionHasNoErrors();

        $target->refresh();
        self::assertSame((string) $oldId, (string) $target->getKey());
        self::assertSame('ssh-demo', $target->target_id);
        self::assertSame('ssh_direct', $target->connector_type);
        self::assertSame('disconnected', $target->connection_state->value);
        self::assertNull($target->last_tested_at);
        self::assertNull($target->connected_at);
        self::assertNull($target->last_success_at);
        self::assertNull($target->last_failure_at);
        self::assertNull($target->last_failure_code);
        $config->refresh();
        self::assertSame(2222, $config->port);
        self::assertNull($config->observed_peer_ip);
        self::assertNull($config->observed_at);
        self::assertNull($config->verification_attempt_id);
        $newCredential = TargetCredential::query()->sole();
        self::assertNotSame($oldCiphertext, $newCredential->encrypted_payload);
        self::assertSame(['secret' => 'test-password-secret', 'passphrase' => null],
            app(SshTargetVault::class)->open($target, $config, $newCredential));
        self::assertDatabaseHas('user_target_access', [
            'user_id' => $operator->getKey(), 'target_record_id' => $oldId, 'allowed' => 1,
        ]);
        self::assertDatabaseHas('target_group_targets', [
            'target_group_id' => $group->getKey(), 'target_record_id' => $oldId,
        ]);
        self::assertDatabaseHas('target_group_users', [
            'target_group_id' => $group->getKey(), 'user_id' => $operator->getKey(),
        ]);
        self::assertSame(1, DB::table('activity_events')
            ->where('operation', 'ssh-target-reconfigure')->where('outcome', 'success')->count());
        $this->get('/admin/targets/ssh-demo')->assertOk()->assertSee('deploy@1.1.1.1:2222');
    }

    public function test_owner_rotates_password_then_switches_to_key_and_switch_requires_new_credential(): void
    {
        $this->actingAs($this->user('owner'));
        $target = $this->ssh();
        $revision = $this->editRevision('ssh-demo');
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_password' => 'updated-test-password',
        ]))->assertRedirect('/admin/targets/ssh-demo');
        $config = SshTargetConfig::query()->sole();
        self::assertSame('updated-test-password', app(SshTargetVault::class)->open(
            $target, $config, TargetCredential::query()->sole(),
        )['secret']);

        $revision = $this->editRevision('ssh-demo');
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_auth_method' => 'private_key',
        ]))->assertSessionHasErrors('ssh_auth_method');
        self::assertSame('password', $config->fresh()->auth_method);
        $revision = $this->editRevision('ssh-demo');
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_auth_method' => 'private_key',
            'ssh_private_key' => EC::createKey('Ed25519')->toString('OpenSSH'),
            'ssh_passphrase' => 'test-key-passphrase',
        ]))->assertRedirect('/admin/targets/ssh-demo');
        $config->refresh();
        self::assertSame('private_key', $config->auth_method);
        $rotated = app(SshTargetVault::class)->open($target, $config, TargetCredential::query()->sole());
        self::assertStringStartsWith('-----BEGIN OPENSSH PRIVATE KEY-----', $rotated['secret']);
        self::assertSame('test-key-passphrase', $rotated['passphrase']);
        $this->get('/admin/targets/ssh-demo/edit')->assertOk()
            ->assertDontSee('updated-test-password')
            ->assertDontSee($rotated['secret'])
            ->assertDontSee('test-key-passphrase');
    }

    public function test_ssh_reconfiguration_rejects_stale_unverified_or_unauthorized_edit_without_secret_leak(): void
    {
        $owner = $this->user('owner');
        $operator = $this->user('operator');
        $this->ssh();
        $this->actingAs($operator)->get('/admin/targets/ssh-demo/edit')->assertForbidden();
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate('faux', [
            'ssh_password' => 'not-authorized',
        ]))->assertForbidden();

        $this->actingAs($owner);
        $revision = $this->editRevision('ssh-demo');
        $wrong = $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_port' => 2222, 'ssh_password' => 'would-leak',
            'current_password' => 'wrong',
        ]))->assertSessionHasErrors('current_password');
        $this->assertNoFlashedSecrets($wrong);
        self::assertSame(22, SshTargetConfig::query()->sole()->port);

        $untrusted = $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_host' => 'attacker.example.test', 'ssh_trust_confirmed' => null,
        ]))->assertSessionHasErrors('ssh_trust_confirmed');
        $this->assertNoFlashedSecrets($untrusted);

        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_port' => 2222,
        ]))->assertRedirect('/admin/targets/ssh-demo');
        $stale = $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_port' => 2223, 'ssh_password' => 'stale-secret',
        ]))->assertSessionHasErrors('configuration_revision');
        $this->assertNoFlashedSecrets($stale);
        self::assertSame(2222, SshTargetConfig::query()->sole()->port);

        $current = $this->editRevision('ssh-demo');
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($current, [
            'ssh_host_key' => 'ssh-ed25519 invalid-key',
        ]))->assertSessionHasErrors('ssh_host');
        self::assertSame(2222, SshTargetConfig::query()->sole()->port);
    }

    public function test_rotation_supersedes_inflight_ssh_verification_and_blocks_commands_until_reverified(): void
    {
        $owner = $this->user('owner');
        $this->actingAs($owner);
        $target = $this->ssh();
        $config = SshTargetConfig::query()->sole();
        $credential = TargetCredential::query()->sole();
        $attempt = app(SshVerificationState::class)->begin($target, $config, $credential);
        $config = $config->fresh();
        $revision = $this->editRevision('ssh-demo');

        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_port' => 2222,
        ]))->assertRedirect('/admin/targets/ssh-demo');

        try {
            app(SshVerificationState::class)->succeeded($target, $config, $credential, $attempt, '1.1.1.1');
            self::fail('Stale SSH verification marked the rotated endpoint as connected.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }
        self::assertSame('disconnected', $target->fresh()->connection_state->value);
        try {
            app(SshCommandRuntime::class)->run($owner, $target, 'whoami');
            self::fail('An unverified SSH endpoint executed a remote command.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('credential_unavailable', $exception->reason);
        }
        try {
            app(SshFileRuntime::class)->stat($owner, $target, '/etc/os-release');
            self::fail('An unverified SSH endpoint opened SFTP.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_not_found', $exception->reason);
        }
    }

    public function test_ssh_key_rotation_rejects_invalid_private_key_without_destroying_old_login(): void
    {
        $this->actingAs($this->user('owner'));
        $this->ssh();
        $oldCredential = TargetCredential::query()->sole()->encrypted_payload;
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($this->editRevision('ssh-demo'), [
            'ssh_auth_method' => 'private_key',
            'ssh_private_key' => 'NOT AN OPENSSH PRIVATE KEY',
        ]))->assertSessionHasErrors('ssh_private_key');
        self::assertSame($oldCredential, TargetCredential::query()->sole()->encrypted_payload);
        self::assertSame('password', SshTargetConfig::query()->sole()->auth_method);
    }

    public function test_noop_owner_ssh_edit_does_not_invalidate_verified_login_or_reencrypt_secrets(): void
    {
        $this->actingAs($this->user('owner'));
        $target = $this->ssh();
        $target->forceFill([
            'connection_state' => TargetConnectionState::Connected,
            'connected_at' => now(),
            'last_success_at' => now(),
        ])->save();

        $revision = $this->editRevision('ssh-demo');
        $cipher = TargetCredential::query()->sole()->encrypted_payload;
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision))
            ->assertRedirect('/admin/targets/ssh-demo')->assertSessionHasNoErrors();
        self::assertSame($cipher, TargetCredential::query()->sole()->encrypted_payload);
        self::assertSame(TargetConnectionState::Connected, $target->fresh()->connection_state);
        self::assertSame(0, DB::table('activity_events')->where('operation', 'ssh-target-reconfigure')->count());
    }

    public function test_unrecognized_stored_connector_cannot_be_reconfigured_through_owner_route(): void
    {
        $this->actingAs($this->user('owner'));
        $target = Target::query()->create([
            'target_id' => 'unrecognized-record',
            'display_name' => 'Unrecognized stored record',
            'connector_type' => 'wp_ai_bridge',
        ]);
        DB::table('targets')->where('id', $target->getKey())
            ->update(['connector_type' => 'unrecognized_connector']);
        $this->get('/admin/targets/unrecognized-record/edit')->assertOk()
            ->assertSee('historical connector does not offer a configuration editor');
        $this->put('/admin/targets/unrecognized-record/configuration', [
            'current_password' => 'CorrectHorse!234',
            'configuration_revision' => str_repeat('1', 64),
        ])->assertNotFound();
        self::assertSame('unrecognized_connector', $target->fresh()->connector_type);
    }

    public function test_disconnected_ssh_target_can_readd_write_only_credential_without_recreating_identity(): void
    {
        $this->actingAs($this->user('owner'));
        $target = $this->ssh();
        $this->post('/admin/targets/ssh-demo/disconnect')->assertRedirect('/admin/targets/ssh-demo');
        self::assertSame(0, TargetCredential::query()->count());

        $revision = $this->editRevision('ssh-demo');
        $this->put('/admin/targets/ssh-demo/configuration', $this->sshUpdate($revision, [
            'ssh_password' => 'new-secret-after-disconnect',
        ]))->assertRedirect('/admin/targets/ssh-demo');
        self::assertSame('ssh-demo', $target->fresh()->target_id);
        self::assertSame('new-secret-after-disconnect', app(SshTargetVault::class)->open(
            $target, SshTargetConfig::query()->sole(), TargetCredential::query()->sole(),
        )['secret']);
    }

    public function test_wordpress_change_is_blocked_until_safe_disconnect_and_reauthorizes_new_origin(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge', 'target_id' => 'wp-demo',
            'display_name' => 'WP Demo', 'base_url' => 'https://old.example.test',
        ])->assertRedirect('/admin/targets/wp-demo');

        $target = Target::query()->where('target_id', 'wp-demo')->sole();
        $firstRevision = $this->editRevision('wp-demo');
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();
        $this->get('/admin/targets/wp-demo/edit')->assertOk()
            ->assertSee('Disconnect WordPress');
        $this->put('/admin/targets/wp-demo/configuration', $this->wpUpdate($firstRevision, 'https://new.example.test'))
            ->assertSessionHasErrors('configuration_revision');
        $config = WpAiBridgeTargetConfig::query()->sole();
        self::assertSame('https://old.example.test', $config->base_url);

        $target->forceFill(['connection_state' => TargetConnectionState::Disconnected])->save();
        $revision = $this->editRevision('wp-demo');
        DB::table('wp_ai_bridge_revocation_intents')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $target->getKey(), 'kind' => 'disconnect',
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->put('/admin/targets/wp-demo/configuration', $this->wpUpdate($revision, 'https://new.example.test'))
            ->assertSessionHasErrors('base_url');
        DB::table('wp_ai_bridge_revocation_intents')->delete();

        $revision = $this->editRevision('wp-demo');
        $this->put('/admin/targets/wp-demo/configuration', $this->wpUpdate($revision, 'https://new.example.test'))
            ->assertRedirect('/admin/targets/wp-demo')->assertSessionHasNoErrors();
        $config->refresh();
        self::assertSame('https://new.example.test', $config->base_url);
        self::assertSame('https://new.example.test', $config->oauth_issuer_url);
        self::assertSame('disconnected', $target->fresh()->connection_state->value);
        self::assertSame('wp-demo', $target->fresh()->target_id);
        self::assertSame(0, TargetCredential::query()->count());
        self::assertSame(1, DB::table('activity_events')
            ->where('operation', 'wordpress-origin-reconfigure')->count());
    }

    public function test_wordpress_pending_oauth_authorization_is_visibly_blocked_before_origin_edit(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge', 'target_id' => 'wp-pending',
            'display_name' => 'Pending OAuth', 'base_url' => 'https://old.example.test',
        ])->assertRedirect('/admin/targets/wp-pending');

        $target = Target::query()->where('target_id', 'wp-pending')->sole();
        $revision = $this->editRevision('wp-pending');
        DB::table('wp_ai_bridge_oauth_flows')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $target->getKey(),
            'state_hash' => str_repeat('4', 64),
            'encrypted_context' => 'fixture-only-invalid-context-not-used',
            'expires_at' => now()->addMinutes(5),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $this->get('/admin/targets/wp-pending/edit')
            ->assertOk()
            ->assertSee('Disconnect WordPress')
            ->assertDontSee('name="base_url"', false);
        $this->put('/admin/targets/wp-pending/configuration', $this->wpUpdate($revision, 'https://new.example.test'))
            ->assertSessionHasErrors('base_url');

        DB::table('wp_ai_bridge_oauth_flows')->delete();
        $this->get('/admin/targets/wp-pending/edit')
            ->assertOk()
            ->assertSee('name="base_url"', false);
    }

    public function test_wordpress_reconfiguration_rejects_unsafe_and_duplicate_origins_without_changing_records(): void
    {
        $this->actingAs($this->user('owner'));
        foreach (['one', 'two'] as $id) {
            $this->post('/admin/targets', [
                'connector_type' => 'wp_ai_bridge', 'target_id' => 'wp-'.$id,
                'display_name' => 'WP '.$id, 'base_url' => 'https://'.$id.'.example.test',
            ])->assertRedirect('/admin/targets/wp-'.$id);
        }
        $revision = $this->editRevision('wp-one');
        $this->put('/admin/targets/wp-one/configuration', $this->wpUpdate($revision, 'https://127.0.0.1'))
            ->assertSessionHasErrors('base_url');
        $this->put('/admin/targets/wp-one/configuration', $this->wpUpdate($revision, 'https://two.example.test'))
            ->assertSessionHasErrors('base_url');
        self::assertSame('https://one.example.test',
            WpAiBridgeTargetConfig::query()->where('base_url', 'https://one.example.test')->sole()->base_url);
        self::assertSame(2, WpAiBridgeTargetConfig::query()->count());
    }

    public function test_wordpress_origin_reconfiguration_reports_localhost_dns_override_without_mutation(): void
    {
        $this->actingAs($this->user('owner'));
        $this->post('/admin/targets', [
            'connector_type' => 'wp_ai_bridge',
            'target_id' => 'wp-dns-override',
            'display_name' => 'WordPress DNS override',
            'base_url' => 'https://old.example.test',
        ])->assertRedirect('/admin/targets/wp-dns-override');

        $target = Target::query()->where('target_id', 'wp-dns-override')->sole();
        $revision = $this->editRevision('wp-dns-override');
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'blocked.example.test' ? ['127.0.0.1'] : ['1.1.1.1'];
            }
        });

        $this->put('/admin/targets/wp-dns-override/configuration', $this->wpUpdate(
            $revision, 'https://blocked.example.test',
        ))->assertSessionHasErrors('base_url')
            ->assertSessionHas('diagnostic_code', 'unsafe_target')
            ->assertSessionHas('diagnostic_context', static fn (array $details): bool => ($details['outbound_rejection_reason'] ?? null) === 'dns_non_public'
                && ($details['outbound_rejected_address'] ?? null) === '127.0.0.1'
            );

        $this->get('/admin/targets/wp-dns-override/edit')->assertOk()
            ->assertSee('127.0.0.1')
            ->assertSee('/etc/hosts')
            ->assertDontSee('CorrectHorse!234');
        self::assertSame('https://old.example.test',
            WpAiBridgeTargetConfig::query()->where('target_record_id', $target->getKey())->sole()->base_url);
        self::assertSame(0, TargetCredential::query()->count());
        self::assertSame(0, DB::table('activity_events')->where('operation', 'wordpress-origin-reconfigure')->count());
        Http::assertSentCount(2); // Initial registration only.
    }

    private function ssh(): Target
    {
        return app(SshTargetRegistration::class)->register(
            'ssh-demo', 'SSH Demo', '1.1.1.1', 22, 'deploy', $this->hostKey(),
            'password', 'test-password-secret', null,
        );
    }

    private function hostKey(): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32));
    }

    /** @param array<string,mixed> $changes
     * @return array<string,mixed>
     */
    private function sshUpdate(string $revision, array $changes = []): array
    {
        return array_replace([
            'configuration_revision' => $revision,
            'ssh_host' => '1.1.1.1',
            'ssh_port' => 22,
            'ssh_username' => 'deploy',
            'ssh_host_key' => $this->hostKey(),
            'ssh_trust_confirmed' => 'yes',
            'ssh_auth_method' => 'password',
            'current_password' => 'CorrectHorse!234',
        ], $changes);
    }

    /** @return array<string,mixed> */
    private function wpUpdate(string $revision, string $url): array
    {
        return [
            'configuration_revision' => $revision,
            'base_url' => $url,
            'current_password' => 'CorrectHorse!234',
        ];
    }

    private function editRevision(string $targetId): string
    {
        return $this->revision($this->get('/admin/targets/'.$targetId.'/edit')->assertOk()->getContent());
    }

    private function revision(string $html): string
    {
        if (! preg_match('/name="configuration_revision" value="([a-f0-9]{64})"/', $html, $m)) {
            self::fail('The secure configuration form and revision were not rendered.');
        }

        return $m[1];
    }

    private function assertNoFlashedSecrets(TestResponse $response): void
    {
        $old = $response->baseResponse->getSession()->getOldInput();
        foreach (['ssh_password', 'ssh_private_key', 'ssh_passphrase', 'current_password'] as $field) {
            self::assertArrayNotHasKey($field, $old);
        }
    }

    private function user(string $role): User
    {
        return User::query()->create([
            'name' => 'Test '.$role,
            'email' => uniqid('config-', true).'@example.test',
            'password' => 'CorrectHorse!234',
            'role' => $role,
            'target_scope_mode' => $role === 'owner' ? 'all' : 'selected',
            'access_enabled' => true,
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
