<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->unsignedSmallInteger('wp_ability_input_kib')->nullable();
            $table->unsignedInteger('dcr_registration_capacity')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn(['wp_ability_input_kib', 'dcr_registration_capacity']);
        });
    }
};
