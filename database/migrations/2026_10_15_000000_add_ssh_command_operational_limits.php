<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            // Older releases ignore additive, nullable columns on rollback.
            // The legacy JSON continues to contain only WP response budgets.
            $table->unsignedTinyInteger('ssh_command_timeout_seconds')->nullable();
            $table->unsignedTinyInteger('ssh_command_max_kib')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn(['ssh_command_timeout_seconds', 'ssh_command_max_kib']);
        });
    }
};
