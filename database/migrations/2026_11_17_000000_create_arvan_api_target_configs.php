<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('arvan_api_target_configs', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->unique()->constrained('targets')->cascadeOnDelete();
            $table->string('base_url', 1024);
            $table->string('spec_url', 1024)->nullable();
            $table->string('probe_path', 1024)->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('arvan_api_target_configs');
    }
};
