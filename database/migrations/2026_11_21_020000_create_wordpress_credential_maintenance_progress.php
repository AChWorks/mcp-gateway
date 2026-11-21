<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('wp_credential_maintenance_progress', static function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
            $table->timestamp('last_due_at')->nullable();
            $table->ulid('last_target_id')->nullable();
            $table->timestamp('updated_at')->nullable();
        });
        DB::table('wp_credential_maintenance_progress')->insert(['id' => 1]);
    }

    public function down(): void
    {
        Schema::dropIfExists('wp_credential_maintenance_progress');
    }
};
