<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_dcr_clients', static function (Blueprint $table): void {
            $table->string('client_id', 64)->primary();
            $table->string('profile_key', 48)->unique();
            $table->char('secret_hash', 64);
            $table->json('redirect_uris');
            $table->string('display_name', 160);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        if (Schema::hasTable('oauth_dcr_clients') && DB::table('oauth_dcr_clients')->exists()) {
            throw new RuntimeException('Cannot drop durable DCR client credentials while registrations exist.');
        }

        Schema::dropIfExists('oauth_dcr_clients');
    }
};
