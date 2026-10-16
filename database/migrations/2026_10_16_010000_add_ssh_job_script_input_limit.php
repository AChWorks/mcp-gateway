<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            // Older releases ignore an additive nullable column, retaining
            // their existing 16 KiB SSH Job script-input budget.
            $table->unsignedTinyInteger('ssh_job_max_script_kib')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn('ssh_job_max_script_kib');
        });
    }
};
