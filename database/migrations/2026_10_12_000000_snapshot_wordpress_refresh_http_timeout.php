<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            // Keep network keys out of legacy JSON: old releases reject
            // unknown keys. A downgraded runtime ignores these columns.
            $table->unsignedTinyInteger('wp_connect_timeout_seconds')->nullable();
            $table->unsignedTinyInteger('wp_request_timeout_seconds')->nullable();
        });

        Schema::table('wp_ai_bridge_refresh_intents', static function (Blueprint $table): void {
            // Nullable for pre-upgrade intents. No credential or secret is
            // stored here; it only fences one uncertain provider exchange.
            $table->unsignedSmallInteger('request_timeout_seconds')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('wp_ai_bridge_refresh_intents', static function (Blueprint $table): void {
            $table->dropColumn('request_timeout_seconds');
        });
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn(['wp_connect_timeout_seconds', 'wp_request_timeout_seconds']);
        });
    }
};
