<?php

namespace Tests\Feature\OAuth;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\DcrClientRegistration;
use App\Infrastructure\OAuth\RefreshTokenInspector;
use App\Models\User;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class DcrOAuthFlowTest extends TestCase
{
    use RefreshDatabase;

    private const CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect';

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('oauth.dcr.registration_enabled', true);
        config()->set('oauth.dcr.cimd_advertise', false);

        Artisan::call('gateway:oauth-keygen', ['--force' => true]);
    }

    public function test_discovery_selects_dcr_without_removing_the_legacy_cimd_profile(): void
    {
        $this->getJson('/.well-known/oauth-authorization-server')
            ->assertOk()
            ->assertJsonPath('registration_endpoint', rtrim((string) config('oauth.issuer'), '/').'/oauth/register')
            ->assertJsonPath('client_id_metadata_document_supported', false)
            ->assertJsonPath('token_endpoint_auth_methods_supported.0', 'private_key_jwt')
            ->assertJsonPath('token_endpoint_auth_methods_supported.1', 'client_secret_post')
            ->assertJsonPath('revocation_endpoint_auth_methods_supported.0', 'private_key_jwt')
            ->assertJsonPath('revocation_endpoint_auth_methods_supported.1', 'client_secret_post')
            ->assertJsonPath('revocation_endpoint_auth_signing_alg_values_supported.0', 'RS256');

        $profile = app(ClientProfileRegistry::class)->active('https://chatgpt.com/oauth/client.json');
        self::assertSame('cimd_private_key_jwt', $profile['strategy'] ?? null);

        self::assertSame(15552000, (int) config('oauth.ttl.refresh_token_seconds'));
        self::assertSame(3600, (int) config('oauth.ttl.access_token_seconds'));
    }

    public function test_disabled_registration_is_not_advertised_but_existing_dcr_clients_stay_valid(): void
    {
        [$client] = $this->registerClient();

        config()->set('oauth.dcr.registration_enabled', false);

        $this->getJson('/.well-known/oauth-authorization-server')->assertJsonMissingPath('registration_endpoint');
        $this->postJson('/oauth/register', $this->registrationMetadata())->assertNotFound();

        self::assertSame(
            'dcr_client_secret_post',
            app(ClientProfileRegistry::class)->active($client['client_id'])['strategy'] ?? null,
        );
    }

    public function test_dcr_auth_code_refresh_recovery_revocation_and_identity_isolation(): void
    {
        [$first, $secret] = $this->registerClient();
        [$second, $secondSecret] = $this->registerClient();
        $user = $this->operator();

        $verifier = str_repeat('v', 64);
        $parameters = $this->authorizationParameters($first['client_id'], $verifier);

        $this->actingAs($user)
            ->get('/oauth/authorize?'.http_build_query($parameters))
            ->assertOk()
            ->assertSee('Authorize ChatGPT')
            ->assertHeader('X-Frame-Options', 'DENY');

        $authorization = $this->actingAs($user)
            ->post('/oauth/authorize', [...$parameters, 'decision' => 'approve']);
        $authorization->assertRedirect();
        $code = $this->redirectCode((string) $authorization->headers->get('Location'));

        $payload = [
            'grant_type' => 'authorization_code',
            'client_id' => $first['client_id'],
            'client_secret' => $secret,
            'redirect_uri' => self::CALLBACK,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
        ];

        $this->post('/oauth/token', [...$payload, 'client_id' => $second['client_id']])
            ->assertUnauthorized();
        $this->post('/oauth/token', [...$payload, 'client_secret' => 'wrong-secret'])
            ->assertUnauthorized();

        $issued = $this->post('/oauth/token', $payload);
        $issued->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
        $access = (string) $issued->json('access_token');
        $refresh = (string) $issued->json('refresh_token');

        $accessParts = explode('.', $access);
        self::assertCount(3, $accessParts);
        $accessClaims = json_decode(JWT::urlsafeB64Decode($accessParts[1]), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($first['client_id'], $accessClaims['aud'] ?? null);
        self::assertSame((string) config('oauth.resource'), DB::table('oauth_access_tokens')
            ->where('client_id', $first['client_id'])->value('resource'));

        self::assertSame(1, DB::table('oauth_authorizations')->where('client_id', $first['client_id'])->count());
        self::assertSame(0, DB::table('oauth_authorizations')->where('client_id', $second['client_id'])->count());

        // A DCR client never needs the ChatGPT CIMD/JWKS fetch.
        $rotate = ['grant_type' => 'refresh_token', 'client_id' => $first['client_id'],
            'client_secret' => $secret, 'refresh_token' => $refresh,
            'resource' => config('oauth.resource')];

        $rotated = $this->post('/oauth/token', $rotate);
        $rotated->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
        self::assertNotSame($refresh, $rotated->json('refresh_token'));

        $recovered = $this->post('/oauth/token', $rotate);
        $recovered->assertOk();
        self::assertSame($rotated->getContent(), $recovered->getContent());

        $this->post('/oauth/token', $rotate)->assertStatus(400);
        self::assertSame(1, DB::table('oauth_refresh_tokens')->whereNull('revoked_at')->count());

        $replacement = (string) $rotated->json('refresh_token');
        $replacementPayload = app(RefreshTokenInspector::class)->inspect($replacement);
        self::assertIsArray($replacementPayload);
        self::assertSame($first['client_id'], $replacementPayload['client_id'] ?? null);

        // Authentication is required before revocation. A different correctly
        // authenticated client still has no authority over this grant.
        $revoke = ['client_id' => $first['client_id'], 'client_secret' => $secret,
            'token' => $replacement, 'token_type_hint' => 'refresh_token'];
        $this->post('/oauth/revoke', [...$revoke, 'client_secret' => 'incorrect-secret'])
            ->assertUnauthorized();
        $this->post('/oauth/revoke', array_diff_key($revoke, ['client_secret' => true]))
            ->assertUnauthorized();
        $this->post('/oauth/revoke', [...$revoke, 'client_assertion' => 'mixed-method'])
            ->assertUnauthorized();
        $this->post('/oauth/revoke', [...$revoke, 'client_id' => $second['client_id'],
            'client_secret' => $secondSecret])->assertOk();
        self::assertSame(0, DB::table('oauth_authorizations')
            ->where('client_id', $first['client_id'])->whereNotNull('revoked_at')->count());

        $this->post('/oauth/revoke', [
            'client_id' => $first['client_id'], 'client_secret' => $secret,
            'token' => $replacement, 'token_type_hint' => 'refresh_token',
        ])->assertOk();

        self::assertSame(1, DB::table('oauth_authorizations')
            ->where('client_id', $first['client_id'])->whereNotNull('revoked_at')->count());
        $this->post('/oauth/token', [...$rotate, 'refresh_token' => $replacement])->assertStatus(400);
    }

    public function test_dcr_authorization_enforces_pkce_resource_and_exact_registered_redirect(): void
    {
        [$client] = $this->registerClient();
        $user = $this->operator();
        $valid = $this->authorizationParameters($client['client_id']);

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            ...$valid, 'code_challenge_method' => 'plain',
        ]))->assertStatus(400);

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            ...$valid, 'resource' => 'https://attacker.example/mcp',
        ]))->assertStatus(400);

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            ...$valid, 'redirect_uri' => 'https://attacker.example/callback',
        ]))->assertUnauthorized();

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            ...$valid, 'scope' => 'offline_access',
        ]))->assertStatus(400);

        self::assertSame(0, DB::table('oauth_authorizations')->count());
        self::assertSame(0, DB::table('oauth_auth_codes')->count());
    }

    public function test_dcr_does_not_inherit_prior_cimd_permissions_and_respects_ai_opt_in(): void
    {
        [$client, $secret] = $this->registerClient();
        $user = $this->operator();
        $user->forceFill(['ai_access_enabled' => false])->save();

        $parameters = $this->authorizationParameters($client['client_id']);
        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query($parameters))->assertForbidden();
        $this->post('/oauth/authorize', [...$parameters, 'decision' => 'approve'])->assertForbidden();
        $this->post('/oauth/token', ['client_id' => $client['client_id'], 'client_secret' => $secret,
            'grant_type' => 'refresh_token', 'resource' => config('oauth.resource'), 'refresh_token' => 'any'])
            ->assertStatus(400);

        self::assertSame(0, DB::table('oauth_authorizations')->count());
        self::assertSame(0, DB::table('oauth_access_tokens')->count());
    }

    public function test_dcr_registration_rejects_bad_callbacks_incompatible_contracts_and_credentials(): void
    {
        $this->withoutMiddleware(ThrottleRequests::class);
        $valid = $this->registrationMetadata();

        $bad = [
            ['redirect_uris' => ['https://attacker.example/callback']],
            ['redirect_uris' => ['http://chatgpt.com/connector_platform_oauth_redirect']],
            ['redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect#fragment']],
            ['redirect_uris' => [self::CALLBACK, self::CALLBACK]],
            ['redirect_uris' => []],
            ['redirect_uris' => 'not-an-array'],
            ['token_endpoint_auth_method' => 'none'],
            ['token_endpoint_auth_method' => 'private_key_jwt'],
            ['grant_types' => ['client_credentials']],
            ['grant_types' => [['nested-array']]],
            ['response_types' => ['token']],
            ['client_name' => ''],
        ];

        foreach ($bad as $overrides) {
            $this->postJson('/oauth/register', array_replace($valid, $overrides))
                ->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');
        }

        $this->post('/oauth/register', $valid)->assertStatus(400);
        $this->call('POST', '/oauth/register', [], [], [], ['CONTENT_TYPE' => 'application/json'], '[]')
            ->assertStatus(400);
        $this->call('POST', '/oauth/register', [], [], [], ['CONTENT_TYPE' => 'application/json'], str_repeat('x', 8200))
            ->assertStatus(400);
        self::assertSame(0, DB::table('oauth_dcr_clients')->count());
    }

    public function test_admin_can_inspect_and_explicitly_revoke_only_a_registered_dcr_identity(): void
    {
        [$client, $secret] = $this->registerClient();
        $owner = User::query()->create([
            'name' => 'Gateway Owner', 'email' => 'dcr-owner@example.test',
            'password' => Hash::make('Test-passphrase-for-only-this-fixture'),
            'role' => GatewayRole::Owner->value, 'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $this->actingAs($owner)->get('/admin/oauth-clients')
            ->assertOk()
            ->assertSee($client['client_id'])
            ->assertSee('dcr_client_secret_post')
            ->assertDontSee($secret);

        Artisan::call('gateway:oauth-client-profile', ['operation' => 'list']);
        self::assertStringContainsString($client['client_id'], Artisan::output());

        Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'disable', 'key' => $this->profileKeyFor($client['client_id']),
        ]);
        self::assertNull(DB::table('oauth_client_profiles')
            ->where('client_id', $client['client_id'])->value('disabled_at'));

        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'disable', 'key' => $this->profileKeyFor($client['client_id']),
            '--confirm' => true,
        ]));
        self::assertNotNull(DB::table('oauth_client_profiles')
            ->where('client_id', $client['client_id'])->value('disabled_at'));
        self::assertNull(app(ClientProfileRegistry::class)->active($client['client_id']));
        self::assertNotSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'enable', 'key' => $this->profileKeyFor($client['client_id']),
            '--confirm' => true,
        ]));
    }

    public function test_registration_rate_limit_prevents_unbounded_client_creation(): void
    {
        $responses = [];
        for ($i = 0; $i < 7; $i++) {
            $responses[] = $this->postJson('/oauth/register', $this->registrationMetadata())->status();
        }
        self::assertSame([201, 201, 201, 201, 201, 429, 429], $responses);
        self::assertSame(5, DB::table('oauth_dcr_clients')->count());
    }

    public function test_dcr_retirement_requires_explicit_disable_and_confirmation_without_reusing_identity(): void
    {
        [$client, $secret] = $this->registerClient();
        [$unaffected] = $this->registerClient();
        $profileKey = $this->profileKeyFor($client['client_id']);

        self::assertNotSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'retire', 'key' => $profileKey,
        ]));
        self::assertNotSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'retire', 'key' => $profileKey, '--confirm' => true,
        ]));
        self::assertSame(0, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());

        app(ClientProfileRegistry::class)->disable($profileKey);

        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'retire', 'key' => $profileKey, '--confirm' => true,
        ]));
        self::assertSame(1, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());
        self::assertSame(2, DB::table('oauth_dcr_clients')->count());
        self::assertNotNull(DB::table('oauth_dcr_clients')->where('client_id', $client['client_id'])
            ->value('secret_hash'));
        self::assertNull(app(ClientProfileRegistry::class)->active($client['client_id']));
        self::assertNotNull(app(ClientProfileRegistry::class)->active($unaffected['client_id']));
        self::assertSame(2, (int) DB::table('oauth_client_profiles')
            ->where('profile_key', $profileKey)->value('generation'));

        // The tombstone and disabled generation survive repeated commands;
        // neither the secret nor the old profile can be resurrected.
        self::assertSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'retire', 'key' => $profileKey, '--confirm' => true,
        ]));
        self::assertNotSame(0, Artisan::call('gateway:oauth-client-profile', [
            'operation' => 'enable', 'key' => $profileKey, '--confirm' => true,
        ]));
        self::assertSame(1, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());

        Artisan::call('gateway:oauth-client-profile', ['operation' => 'list']);
        self::assertStringContainsString('retired (permanent)', Artisan::output());

        $owner = User::query()->create([
            'name' => 'Retirement Owner', 'email' => 'retirement-owner@example.test',
            'password' => Hash::make('Only-a-test-fixture-secret'),
            'role' => GatewayRole::Owner->value, 'target_scope_mode' => TargetScopeMode::All->value,
            'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $this->actingAs($owner)->get('/admin/oauth-clients')
            ->assertOk()->assertSee('Retired (permanent)')->assertDontSee($secret);
    }

    public function test_dcr_retirement_refuses_unrevoked_grants_and_preserves_existing_token_history(): void
    {
        [$client, $secret] = $this->registerClient();
        $profileKey = $this->profileKeyFor($client['client_id']);
        $user = $this->operator();
        $verifier = str_repeat('v', 64);
        $parameters = $this->authorizationParameters($client['client_id'], $verifier);
        $redirect = $this->actingAs($user)->post('/oauth/authorize', [
            ...$parameters, 'decision' => 'approve',
        ])->assertRedirect();
        $code = $this->redirectCode((string) $redirect->headers->get('Location'));

        $issued = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => $client['client_id'],
            'client_secret' => $secret, 'code' => $code, 'code_verifier' => $verifier,
            'redirect_uri' => self::CALLBACK, 'resource' => config('oauth.resource'),
        ])->assertOk();
        $oldRefresh = (string) $issued->json('refresh_token');
        self::assertNotSame('', $oldRefresh);

        $registry = app(ClientProfileRegistry::class);
        $registry->disable($profileKey);

        try {
            $registry->retireDcr($profileKey);
            self::fail('Retirement must reject a remaining unrevoked consent.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('Revoke every client authorization', $exception->getMessage());
        }
        self::assertSame(0, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());

        // Revoking the parent consent makes ALL its FK-bound codes, access
        // tokens, refresh tokens and recovery envelopes unusable. Do not
        // delete the child/history rows to reclaim a registration slot.
        $authorizationId = DB::table('oauth_authorizations')->where('client_id', $client['client_id'])
            ->value('id');
        self::assertNotNull($authorizationId);
        DB::table('oauth_authorizations')->where('id', $authorizationId)
            ->update(['revoked_at' => now(), 'updated_at' => now()]);
        self::assertSame(1, DB::table('oauth_access_tokens')
            ->where('client_id', $client['client_id'])->count());
        self::assertSame(1, DB::table('oauth_refresh_tokens')
            ->where('client_id', $client['client_id'])->count());

        $registry->retireDcr($profileKey);
        self::assertNotNull(DB::table('oauth_dcr_clients')->where('profile_key', $profileKey)
            ->value('retired_at'));
        self::assertSame(1, DB::table('oauth_access_tokens')
            ->where('client_id', $client['client_id'])->count());
        self::assertSame(1, DB::table('oauth_refresh_tokens')
            ->where('client_id', $client['client_id'])->count());
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => $client['client_id'],
            'client_secret' => $secret, 'refresh_token' => $oldRefresh,
            'resource' => config('oauth.resource'),
        ])->assertUnauthorized();
        app(ClientProfileRegistry::class)->assertReady();
    }

    public function test_dcr_retirement_restores_capacity_with_tombstones_retained(): void
    {
        // Seed 512 structurally valid dormant registered clients without using
        // the public HTTP throttle or any real Gateway credential.
        $profileRows = [];
        $clientRows = [];
        for ($i = 0; $i < 512; $i++) {
            $id = 'dcr_'.str_pad(dechex($i), 48, '0', STR_PAD_LEFT);
            $key = 'dcr_'.str_pad(dechex($i), 32, '0', STR_PAD_LEFT);
            $profileRows[] = ['profile_key' => $key, 'client_id' => $id,
                'auth_strategy' => 'dcr_client_secret_post', 'generation' => 1,
                'disabled_at' => null, 'created_at' => now(), 'updated_at' => now()];
            $clientRows[] = ['client_id' => $id, 'profile_key' => $key,
                'secret_hash' => hash('sha256', $id),
                'redirect_uris' => json_encode([self::CALLBACK], JSON_THROW_ON_ERROR),
                'display_name' => 'ChatGPT (DCR)', 'retired_at' => null,
                'created_at' => now(), 'updated_at' => now()];
        }
        foreach (array_chunk($profileRows, 60) as $chunk) {
            DB::table('oauth_client_profiles')->insert($chunk);
        }
        foreach (array_chunk($clientRows, 60) as $chunk) {
            DB::table('oauth_dcr_clients')->insert($chunk);
        }

        $registration = app(DcrClientRegistration::class);
        try {
            $registration->register($this->registrationMetadata());
            self::fail('Registration must reject exactly 512 occupied slots.');
        } catch (\RuntimeException $exception) {
            self::assertStringContainsString('capacity is unavailable', $exception->getMessage());
        }
        self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());

        // Reclaim a dormant disabled registration without deleting its
        // immutable identity. No existing registered profile is reactivated.
        $registry = app(ClientProfileRegistry::class);
        $retiredKey = $profileRows[0]['profile_key'];
        $registry->disable($retiredKey);
        $registry->retireDcr($retiredKey);

        $fresh = $registration->register($this->registrationMetadata());
        self::assertMatchesRegularExpression('/^dcr_[0-9a-f]{48}$/D', $fresh['client_id']);
        self::assertSame(513, DB::table('oauth_dcr_clients')->count());
        self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
        self::assertSame(1, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());
        self::assertSame(2, (int) DB::table('oauth_client_profiles')
            ->where('profile_key', $retiredKey)->value('generation'));
        self::assertNotNull($registry->active($profileRows[1]['client_id']));
        self::assertNull($registry->active($profileRows[0]['client_id']));
    }

    public function test_dcr_refresh_ttl_is_extended_by_rotation_without_regranting_or_reenabling(): void
    {
        [$client, $secret] = $this->registerClient();
        $user = $this->operator();
        $verifier = str_repeat('v', 64);
        $parameters = $this->authorizationParameters($client['client_id'], $verifier);
        $authorization = $this->actingAs($user)
            ->post('/oauth/authorize', [...$parameters, 'decision' => 'approve']);
        $authorization->assertRedirect();

        $issued = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => $client['client_id'],
            'client_secret' => $secret, 'redirect_uri' => self::CALLBACK,
            'code' => $this->redirectCode((string) $authorization->headers->get('Location')),
            'code_verifier' => $verifier, 'resource' => config('oauth.resource'),
        ])->assertOk();

        $old = (string) $issued->json('refresh_token');
        $oldPayload = app(RefreshTokenInspector::class)->inspect($old);
        self::assertIsArray($oldPayload);
        self::assertGreaterThan(time() + 15550000, $oldPayload['expire_time']);

        // League OAuth creates DateTimeImmutable directly; Laravel's test clock
        // does not alter its token expiry. Cross a real second boundary.
        sleep(2);

        $rotated = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client['client_id'],
            'client_secret' => $secret, 'refresh_token' => $old,
            'resource' => config('oauth.resource'),
        ])->assertOk();

        $updated = app(RefreshTokenInspector::class)->inspect((string) $rotated->json('refresh_token'));
        self::assertIsArray($updated);
        self::assertGreaterThan($oldPayload['expire_time'], $updated['expire_time']);
        self::assertSame(1, DB::table('oauth_authorizations')->count());
    }

    public function test_dcr_migration_refuses_to_discard_a_registered_client(): void
    {
        $this->registerClient();

        $migration = require database_path('migrations/2026_10_24_000000_create_oauth_dcr_clients.php');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot drop durable DCR client credentials');
        $migration->down();
    }

    public function test_dcr_registration_never_persists_plaintext_secret_and_can_preflight(): void
    {
        [$client, $secret] = $this->registerClient();

        $stored = DB::table('oauth_dcr_clients')->where('client_id', $client['client_id'])->first();
        self::assertNotNull($stored);
        self::assertSame(hash('sha256', $secret), $stored->secret_hash);
        self::assertStringNotContainsString($secret, json_encode($stored, JSON_THROW_ON_ERROR));
        self::assertSame('dcr_client_secret_post', DB::table('oauth_client_profiles')
            ->where('client_id', $client['client_id'])->value('auth_strategy'));

        app(ClientProfileRegistry::class)->assertReady();
    }

    private function profileKeyFor(string $clientId): string
    {
        return (string) DB::table('oauth_dcr_clients')->where('client_id', $clientId)
            ->value('profile_key');
    }

    /** @return array{0: array<string, mixed>, 1: string} */
    private function registerClient(): array
    {
        $response = $this->postJson('/oauth/register', $this->registrationMetadata())->assertCreated();
        $metadata = $response->json();

        self::assertIsArray($metadata);
        self::assertMatchesRegularExpression('/^dcr_[0-9a-f]{48}$/D', $metadata['client_id']);
        self::assertSame(0, $metadata['client_secret_expires_at']);
        self::assertSame('client_secret_post', $metadata['token_endpoint_auth_method']);
        self::assertSame([self::CALLBACK], $metadata['redirect_uris']);

        return [$metadata, (string) $metadata['client_secret']];
    }

    /** @return array<string, mixed> */
    private function registrationMetadata(): array
    {
        return ['client_name' => 'ChatGPT', 'redirect_uris' => [self::CALLBACK],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'], 'token_endpoint_auth_method' => 'client_secret_post'];
    }

    /** @return array<string, string> */
    private function authorizationParameters(string $clientId, string $verifier = 'vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv'): array
    {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return ['response_type' => 'code', 'client_id' => $clientId, 'redirect_uri' => self::CALLBACK,
            'scope' => 'mcp', 'state' => 'state-'.Str::uuid(), 'code_challenge' => $challenge,
            'code_challenge_method' => 'S256', 'resource' => (string) config('oauth.resource')];
    }

    private function redirectCode(string $location): string
    {
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        self::assertSame((string) config('oauth.issuer'), $query['iss'] ?? null);
        self::assertIsString($query['code'] ?? null);

        return $query['code'];
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'DCR Test Operator', 'email' => 'dcr-operator@example.test',
            'password' => 'Test-only-not-a-real-password',
            'role' => GatewayRole::Operator->value,
            'target_scope_mode' => TargetScopeMode::Selected->value,
            'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
    }
}
