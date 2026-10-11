<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('operational_settings', function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
            $table->json('overrides');
            $table->unsignedBigInteger('version')->default(0);
            $table->foreignId('changed_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();
        });
        DB::table('operational_settings')->insert([
            'id' => 1,
            'overrides' => '{}',
            'version' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Schema::create('operational_setting_changes', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('setting_key', 64);
            $table->unsignedInteger('previous_value')->nullable();
            $table->unsignedInteger('new_value')->nullable();
            $table->unsignedBigInteger('version');
            $table->foreignId('actor_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('created_at');
            $table->index(['setting_key', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('operational_setting_changes');
        Schema::dropIfExists('operational_settings');
    }
};
