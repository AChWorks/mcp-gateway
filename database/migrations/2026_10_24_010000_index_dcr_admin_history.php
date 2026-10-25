<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Durable retired DCR identities are never deleted. Keep Admin's
        // newest-first bounded listing indexable as their history grows.
        Schema::table('oauth_dcr_clients', static function (Blueprint $table): void {
            $table->index(['created_at', 'client_id'], 'oauth_dcr_clients_admin_history');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_dcr_clients', static function (Blueprint $table): void {
            $table->dropIndex('oauth_dcr_clients_admin_history');
        });
    }
};
