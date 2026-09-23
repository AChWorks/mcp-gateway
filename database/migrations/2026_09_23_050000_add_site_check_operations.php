<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('site_check_operations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignId('creator_user_id')->constrained('users')->cascadeOnDelete();
            $table->uuid('idempotency_key');
            $table->unsignedTinyInteger('active_slot')->nullable();
            $table->string('status', 32);
            $table->timestamp('started_at', 6)->nullable();
            $table->timestamp('completed_at', 6)->nullable();
            $table->timestamps(6);

            $table->unique(
                ['creator_user_id', 'idempotency_key'],
                'site_check_creator_idempotency_unique',
            );
            $table->unique(
                ['creator_user_id', 'active_slot'],
                'site_check_creator_active_unique',
            );
            $table->index(['completed_at', 'id'], 'site_check_completed_idx');
        });

        Schema::create('site_check_operation_targets', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUuid('operation_id')
                ->constrained('site_check_operations')
                ->cascadeOnDelete();
            $table->foreignUlid('site_record_id')
                ->nullable()
                ->constrained('sites')
                ->nullOnDelete();
            $table->unsignedTinyInteger('position');
            $table->string('site_id_snapshot', 64);
            $table->string('display_name_snapshot', 160);
            $table->string('status', 32);
            $table->unsignedTinyInteger('attempts')->default(0);
            $table->uuid('attempt_token')->nullable();
            $table->string('error_code', 64)->nullable();
            $table->timestamp('started_at', 6)->nullable();
            $table->timestamp('finished_at', 6)->nullable();
            $table->timestamps(6);

            $table->unique(
                ['operation_id', 'position'],
                'site_check_target_position_unique',
            );
            $table->unique(
                ['operation_id', 'site_id_snapshot'],
                'site_check_target_site_unique',
            );
            $table->index(
                ['operation_id', 'status', 'position'],
                'site_check_target_claim_idx',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('site_check_operation_targets');
        Schema::dropIfExists('site_check_operations');
    }
};
