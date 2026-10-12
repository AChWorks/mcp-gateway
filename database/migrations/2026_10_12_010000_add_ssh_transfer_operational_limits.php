<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            // Old Gateway versions ignore these columns on rollback. The
            // legacy overrides JSON stays strictly WordPress-response-only.
            $table->unsignedInteger('ssh_transfer_max_kib')->nullable();
            $table->unsignedTinyInteger('ssh_transfer_max_seconds')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn(['ssh_transfer_max_kib', 'ssh_transfer_max_seconds']);
        });
    }
};
