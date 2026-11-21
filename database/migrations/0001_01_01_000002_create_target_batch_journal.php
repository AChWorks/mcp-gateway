<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('target_batches', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->unsignedBigInteger('actor_user_id'); // retain evidence after user removal
            $table->string('source_channel', 16); // trusted HTTP/Web or MCP origin
            $table->string('client_id', 255)->nullable();
            $table->string('client_identity_hash', 64);
            $table->string('client_profile_key', 48)->nullable();
            $table->unsignedInteger('client_profile_generation')->nullable();
            $table->char('authorization_id', 26)->nullable();
            $table->char('resource_hash', 64)->nullable();
            $table->uuid('request_id');
            $table->char('request_fingerprint', 64);
            $table->string('capability_key', 80);
            $table->longText('arguments_ciphertext');
            $table->string('execution_mode', 16); // concurrent | rolling
            $table->boolean('stop_on_failure')->default(false);
            $table->unsignedInteger('parallelism');
            $table->unsignedBigInteger('target_count');
            $table->string('status', 24)->default('queued');
            $table->timestamp('cancel_requested_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();
            $table->unique(['actor_user_id', 'client_identity_hash', 'request_id'], 'target_batch_dedup');
            $table->index(['status', 'created_at'], 'target_batch_active');
        });
        Schema::create('target_batch_items', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('batch_id');
            $table->ulid('target_record_id')->nullable(); // preserve forbidden/unknown selection without disclosing a record
            $table->string('target_id_snapshot', 64);
            $table->string('connector_type_snapshot', 32);
            $table->char('target_binding_hash', 64)->nullable();
            $table->unsignedBigInteger('position');
            $table->string('status', 24)->default('queued');
            $table->uuid('dispatch_attempt_id')->nullable();
            $table->timestamp('lease_expires_at')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->string('error_code', 64)->nullable();
            $table->longText('result_ciphertext')->nullable();
            $table->uuid('diagnostic_reference')->nullable();
            $table->timestamps();
            $table->foreign('batch_id')->references('id')->on('target_batches')->restrictOnDelete();
            $table->unique(['batch_id', 'position'], 'target_batch_position');
            $table->unique(['batch_id', 'target_id_snapshot'], 'target_batch_unique_target');
            $table->index(['batch_id', 'status', 'position'], 'target_batch_claim');
            $table->index(['status', 'lease_expires_at'], 'target_batch_lease');
        });
    }

    public function down(): void
    {
        if (DB::table('target_batch_items')->exists() || DB::table('target_batches')->exists()) {
            throw new RuntimeException('Cannot roll back retained Target Batch execution or uncertain remote effects. Restore a full database backup.');
        }
        Schema::dropIfExists('target_batch_items');
        Schema::dropIfExists('target_batches');
    }
};
