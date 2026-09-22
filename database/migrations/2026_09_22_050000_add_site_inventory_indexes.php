<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('sites', function (Blueprint $table): void {
            $table->index(['display_name', 'site_id'], 'sites_display_name_site_id_index');
            $table->index(
                ['connection_state', 'display_name', 'site_id'],
                'sites_state_display_name_site_id_index',
            );
        });
    }

    public function down(): void
    {
        Schema::table('sites', function (Blueprint $table): void {
            $table->dropIndex('sites_state_display_name_site_id_index');
            $table->dropIndex('sites_display_name_site_id_index');
        });
    }
};
