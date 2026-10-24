<?php

namespace Tests\Feature\OAuth;

use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\DcrClientRegistration;
use App\Infrastructure\OAuth\DcrRegistrationRateLimited;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Tests\TestCase;

final class DcrRegistrationAbuseTest extends TestCase
{
    use RefreshDatabase;

    private const CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect';

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('oauth.dcr.registration_enabled', true);
    }

    public function test_global_success_budget_blocks_distributed_registrations_without_spending_on_invalid_metadata(): void
    {
        for ($i = 1; $i <= 20; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.$i])
                ->postJson('/oauth/register', ['redirect_uris' => ['https://evil.example.invalid/callback']])
                ->assertBadRequest();
        }
        self::assertSame(0, DB::table('oauth_dcr_clients')->count());

        for ($i = 1; $i <= 15; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.$i])
                ->postJson('/oauth/register', $this->registrationMetadata())->assertCreated();
        }

        $limited = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.16'])
            ->postJson('/oauth/register', $this->registrationMetadata())
            ->assertTooManyRequests()
            ->assertHeader('Retry-After')
            ->assertJsonPath('error', 'slow_down');
        self::assertGreaterThan(0, (int) $limited->headers->get('Retry-After'));
        self::assertSame(15, DB::table('oauth_dcr_clients')->count());
    }

    public function test_admission_reclaims_only_expired_never_authorized_registrations(): void
    {
        // 512 durable identities, two old: one never consented and one with
        // a real (now revoked) grant. A former grant must never be auto-retired.
        $this->seedRegisteredClients(512);
        $expired = $this->client(0);
        $historical = $this->client(1);
        $old = now()->subHours(25);
        DB::table('oauth_dcr_clients')->whereIn('client_id', [$expired['id'], $historical['id']])
            ->update(['created_at' => $old, 'updated_at' => $old]);

        $user = User::query()->create([
            'name' => 'Gateway Tester',
            'email' => 'existing-grant@example.test',
            'password' => 'CorrectHorse!234',
        ]);
        $resource = (string) config('oauth.resource');
        DB::table('oauth_authorizations')->insert([
            'id' => (string) Str::ulid(),
            'user_id' => $user->id,
            'client_id' => $historical['id'],
            'client_profile_key' => $historical['profile'],
            'client_profile_generation' => 1,
            'resource' => $resource,
            'resource_hash' => hash('sha256', $resource),
            'scopes' => json_encode(['mcp'], JSON_THROW_ON_ERROR),
            'revoked_at' => now()->subMinutes(30),
            'created_at' => $old,
            'updated_at' => now(),
        ]);

        $registered = app(DcrClientRegistration::class)->register($this->registrationMetadata());

        self::assertSame(513, DB::table('oauth_dcr_clients')->count());
        self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
        self::assertNotNull(DB::table('oauth_dcr_clients')->where('client_id', $expired['id'])->value('retired_at'));
        self::assertNotNull(DB::table('oauth_client_profiles')->where('profile_key', $expired['profile'])->value('disabled_at'));
        self::assertSame(2, (int) DB::table('oauth_client_profiles')->where('profile_key', $expired['profile'])->value('generation'));
        self::assertNull(app(ClientProfileRegistry::class)->active($expired['id']));

        self::assertNull(DB::table('oauth_dcr_clients')->where('client_id', $historical['id'])->value('retired_at'));
        self::assertNotNull(app(ClientProfileRegistry::class)->active($historical['id']));
        self::assertNotNull(app(ClientProfileRegistry::class)->active((string) $registered['client_id']));
        self::assertSame(1, DB::table('oauth_authorizations')->where('client_id', $historical['id'])->count());
    }

    public function test_rate_rejected_registration_never_retires_even_an_expired_orphan(): void
    {
        $this->seedRegisteredClients(512);
        $candidate = $this->client(0);
        DB::table('oauth_dcr_clients')->where('client_id', $candidate['id'])
            ->update(['created_at' => now()->subHours(25)]);

        $budget = 'oauth-dcr:successful-registrations:global';
        for ($i = 0; $i < 15; $i++) {
            RateLimiter::hit($budget, 3600);
        }

        try {
            app(DcrClientRegistration::class)->register($this->registrationMetadata());
            self::fail('Exhausted global budget must reject before database side effects.');
        } catch (DcrRegistrationRateLimited $exception) {
            self::assertGreaterThan(0, $exception->retryAfterSeconds);
        }

        self::assertNull(DB::table('oauth_dcr_clients')->where('client_id', $candidate['id'])->value('retired_at'));
        self::assertNull(DB::table('oauth_client_profiles')->where('profile_key', $candidate['profile'])->value('disabled_at'));
        self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
    }

    public function test_young_unconsented_clients_are_not_retired_under_capacity_pressure(): void
    {
        $this->seedRegisteredClients(512);
        try {
            app(DcrClientRegistration::class)->register($this->registrationMetadata());
            self::fail('Young pending registrations must not be retired.');
        } catch (\RuntimeException $exception) {
            self::assertNotInstanceOf(DcrRegistrationRateLimited::class, $exception);
            self::assertStringContainsString('capacity is unavailable', $exception->getMessage());
        }

        self::assertSame(512, DB::table('oauth_dcr_clients')->whereNull('retired_at')->count());
        self::assertSame(0, DB::table('oauth_dcr_clients')->whereNotNull('retired_at')->count());
    }

    public function test_registered_dcr_profile_with_consent_survives_closing_public_registration(): void
    {
        $client = app(DcrClientRegistration::class)->register($this->registrationMetadata());
        config()->set('oauth.dcr.registration_enabled', false);

        self::assertNotNull(app(ClientProfileRegistry::class)->active((string) $client['client_id']));
        $this->postJson('/oauth/register', $this->registrationMetadata())->assertNotFound();
    }

    /** @return array{profile:string,id:string} */
    private function client(int $index): array
    {
        return [
            'profile' => 'dcr_'.str_pad(dechex($index), 32, '0', STR_PAD_LEFT),
            'id' => 'dcr_'.str_pad(dechex($index), 48, '0', STR_PAD_LEFT),
        ];
    }

    private function seedRegisteredClients(int $count): void
    {
        $profiles = [];
        $registrations = [];
        for ($i = 0; $i < $count; $i++) {
            $client = $this->client($i);
            $profiles[] = [
                'profile_key' => $client['profile'],
                'client_id' => $client['id'],
                'auth_strategy' => 'dcr_client_secret_post',
                'generation' => 1,
                'disabled_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ];
            $registrations[] = [
                'client_id' => $client['id'],
                'profile_key' => $client['profile'],
                'secret_hash' => hash('sha256', $client['id']),
                'redirect_uris' => json_encode([self::CALLBACK], JSON_THROW_ON_ERROR),
                'display_name' => 'ChatGPT (DCR)',
                'retired_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }
        foreach (array_chunk($profiles, 50) as $chunk) {
            DB::table('oauth_client_profiles')->insert($chunk);
        }
        foreach (array_chunk($registrations, 50) as $chunk) {
            DB::table('oauth_dcr_clients')->insert($chunk);
        }
    }

    /** @return array<string, mixed> */
    private function registrationMetadata(): array
    {
        return [
            'client_name' => 'ChatGPT',
            'redirect_uris' => [self::CALLBACK],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'client_secret_post',
        ];
    }
}
