<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('activity_retention_state', function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
        });

        DB::table('activity_retention_state')->insert(['id' => 1]);

        Schema::create('activity_events', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->uuid('correlation_id')->index();
            $table->string('actor_type', 32);
            $table->string('actor_id', 128)->nullable();
            $table->char('client_id_hash', 64)->nullable()->index();
            $table->string('site_id', 128)->nullable()->index();
            $table->string('operation', 128)->index();
            $table->string('outcome', 32)->index();
            $table->string('error_code', 64)->nullable()->index();
            $table->timestamp('created_at')->useCurrent()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('activity_events');
        Schema::dropIfExists('activity_retention_state');
    }
};
