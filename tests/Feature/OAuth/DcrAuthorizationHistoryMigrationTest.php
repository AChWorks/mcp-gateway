<?php

namespace Tests\Feature\OAuth;

use App\Models\User;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-concurrency')]
final class DcrAuthorizationHistoryMigrationTest extends TestCase
{
    public function test_migration_backfills_positive_consent_and_preserves_unknown_legacy_history(): void
    {
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('Test the live column migration on disposable MariaDB/MySQL.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);

        // Simulate the schema state immediately before this additive migration.
        Schema::table('oauth_dcr_clients', static function (Blueprint $table): void {
            $table->dropIndex('oauth_dcr_clients_reclaim');
            $table->dropColumn(['ever_authorized_at', 'auto_retirement_eligible']);
        });

        foreach ([0, 1] as $index) {
            $clientId = 'dcr_'.str_pad(dechex($index), 48, '0', STR_PAD_LEFT);
            $profileKey = 'dcr_'.str_pad(dechex($index), 32, '0', STR_PAD_LEFT);
            DB::table('oauth_client_profiles')->insert([
                'profile_key' => $profileKey, 'client_id' => $clientId,
                'auth_strategy' => 'dcr_client_secret_post', 'generation' => 1,
                'disabled_at' => null, 'created_at' => now(), 'updated_at' => now(),
            ]);
            DB::table('oauth_dcr_clients')->insert([
                'client_id' => $clientId, 'profile_key' => $profileKey,
                'secret_hash' => hash('sha256', $clientId),
                'redirect_uris' => json_encode(['https://chatgpt.com/connector_platform_oauth_redirect'], JSON_THROW_ON_ERROR),
                'display_name' => 'ChatGPT (DCR)', 'retired_at' => null,
                'created_at' => now()->subDays(45), 'updated_at' => now(),
            ]);
        }

        $user = User::query()->create([
            'name' => 'Historical User', 'email' => 'historical@example.test',
            'password' => 'CorrectHorse!234', 'ai_access_enabled' => true,
        ]);
        $usedClient = 'dcr_'.str_pad('0', 48, '0', STR_PAD_LEFT);
        $unusedClient = 'dcr_'.str_pad('1', 48, '0', STR_PAD_LEFT);
        $resource = (string) config('oauth.resource');
        DB::table('oauth_authorizations')->insert([
            'id' => (string) Str::ulid(),
            'client_id' => $usedClient, 'client_profile_key' => 'dcr_'.str_pad('0', 32, '0', STR_PAD_LEFT),
            'client_profile_generation' => 1, 'user_id' => $user->id,
            'resource' => $resource, 'resource_hash' => hash('sha256', $resource),
            'scopes' => json_encode(['mcp'], JSON_THROW_ON_ERROR),
            'revoked_at' => now(), 'created_at' => now()->subDays(20), 'updated_at' => now(),
        ]);

        $migration = require base_path('database/migrations/2026_10_24_020000_track_dcr_authorization_history.php');
        $migration->up();

        self::assertNotNull(DB::table('oauth_dcr_clients')->where('client_id', $usedClient)->value('ever_authorized_at'));
        self::assertFalse((bool) DB::table('oauth_dcr_clients')->where('client_id', $usedClient)->value('auto_retirement_eligible'));
        self::assertNull(DB::table('oauth_dcr_clients')->where('client_id', $unusedClient)->value('ever_authorized_at'));
        self::assertFalse((bool) DB::table('oauth_dcr_clients')->where('client_id', $unusedClient)->value('auto_retirement_eligible'));

        $user->delete();
        self::assertSame(0, DB::table('oauth_authorizations')->where('client_id', $usedClient)->count());
        self::assertNotNull(DB::table('oauth_dcr_clients')->where('client_id', $usedClient)->value('ever_authorized_at'));

        try {
            $migration->down();
            self::fail('Removing durable authorization witness while any DCR exists must fail.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Cannot discard durable DCR consent history', $exception->getMessage());
        }
        self::assertTrue(Schema::hasColumn('oauth_dcr_clients', 'ever_authorized_at'));
    }
}
