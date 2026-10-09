<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_client_profiles', static function (Blueprint $table): void {
            $table->string('profile_key', 48)->primary();
            $table->string('client_id', 255)->unique();
            $table->string('auth_strategy', 48);
            $table->unsignedInteger('generation')->default(1);
            $table->timestamp('disabled_at')->nullable();
            $table->timestamps();
        });

        // Preserve the original ChatGPT protocol identity and generation for
        // existing authorizations. Unknown/unsupported historical client IDs do
        // not acquire another profile's authority.
        DB::table('oauth_client_profiles')->insert([
            'profile_key' => 'chatgpt',
            'client_id' => (string) config('oauth.client.id'),
            'auth_strategy' => 'cimd_private_key_jwt',
            'generation' => 1,
            'disabled_at' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Schema::table('oauth_authorizations', static function (Blueprint $table): void {
            $table->string('client_profile_key', 48)->nullable()->index();
            $table->unsignedInteger('client_profile_generation')->nullable();
        });

        DB::table('oauth_authorizations')
            ->where('client_id', (string) config('oauth.client.id'))
            ->update([
                'client_profile_key' => 'chatgpt',
                'client_profile_generation' => 1,
            ]);

        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->string('client_profile_key', 48)->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->dropColumn('client_profile_key');
        });
        Schema::table('oauth_authorizations', static function (Blueprint $table): void {
            $table->dropColumn(['client_profile_key', 'client_profile_generation']);
        });
        Schema::dropIfExists('oauth_client_profiles');
    }
};
