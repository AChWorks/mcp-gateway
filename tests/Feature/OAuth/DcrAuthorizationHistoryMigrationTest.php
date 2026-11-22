<?php

namespace Tests\Feature\OAuth;

use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

/** V3 starts with the final durable DCR consent schema, not a v2 backfill. */
#[Group('database-concurrency')]
final class DcrAuthorizationHistoryMigrationTest extends TestCase
{
    public function test_fresh_v3_dcr_consent_witness_survives_user_and_grant_deletion(): void
    {
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('Validate durable DCR consent on isolated MariaDB/MySQL.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
        self::assertTrue(Schema::hasColumn('oauth_dcr_clients', 'ever_authorized_at'));
        self::assertTrue(Schema::hasColumn('oauth_dcr_clients', 'auto_retirement_eligible'));

        foreach ([0, 1] as $index) {
            $clientId = 'dcr_'.str_pad(dechex($index), 48, '0', STR_PAD_LEFT);
            $profileKey = 'dcr_'.str_pad(dechex($index), 32, '0', STR_PAD_LEFT);
            DB::table('oauth_client_profiles')->insert([
                'profile_key' => $profileKey, 'client_id' => $clientId,
                'auth_strategy' => 'dcr_client_secret_post', 'generation' => 1,
                'created_at' => now(), 'updated_at' => now(),
            ]);
            DB::table('oauth_dcr_clients')->insert([
                'client_id' => $clientId, 'profile_key' => $profileKey,
                'secret_hash' => hash('sha256', $clientId),
                'redirect_uris' => json_encode(['https://chatgpt.com/connector_platform_oauth_redirect'], JSON_THROW_ON_ERROR),
                'display_name' => 'ChatGPT (DCR)',
                'auto_retirement_eligible' => true, 'ever_authorized_at' => null,
                'created_at' => now()->subDays(45), 'updated_at' => now(),
            ]);
        }

        $user = User::query()->create([
            'name' => 'V3 Consent User', 'email' => 'v3-consent@example.test',
            'password' => 'CorrectHorse!234', 'ai_access_enabled' => true,
        ]);
        $usedClient = 'dcr_'.str_pad('0', 48, '0', STR_PAD_LEFT);
        $unusedClient = 'dcr_'.str_pad('1', 48, '0', STR_PAD_LEFT);
        $authorization = app(OAuthAuthorizationStore::class)->approve(
            $user->id, $usedClient, (string) config('oauth.resource'), ['mcp'],
        );
        self::assertSame($authorization, DB::table('oauth_authorizations')
            ->where('client_id', $usedClient)->value('id'));
        self::assertNotNull(DB::table('oauth_dcr_clients')->where('client_id', $usedClient)
            ->value('ever_authorized_at'));
        self::assertFalse((bool) DB::table('oauth_dcr_clients')->where('client_id', $usedClient)
            ->value('auto_retirement_eligible'));
        self::assertNull(DB::table('oauth_dcr_clients')->where('client_id', $unusedClient)
            ->value('ever_authorized_at'));
        self::assertTrue((bool) DB::table('oauth_dcr_clients')->where('client_id', $unusedClient)
            ->value('auto_retirement_eligible'));

        $user->delete();
        self::assertSame(0, DB::table('oauth_authorizations')->where('client_id', $usedClient)->count());
        self::assertNotNull(DB::table('oauth_dcr_clients')->where('client_id', $usedClient)
            ->value('ever_authorized_at'));

        $baseline = require database_path('migrations/0001_01_01_000001_create_gateway_v3_schema.php');
        try {
            $baseline->down();
            self::fail('V3 cannot erase DCR consent history through a destructive baseline rollback.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Do not roll back the Gateway v3 baseline', $exception->getMessage());
        }
    }
}
