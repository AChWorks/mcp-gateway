<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // One DB-row lock serializes capacity accounting across PHP workers
        // and Gateway nodes using the SAME authoritative database.
        Schema::create('chatgpt_file_admission_guard', static function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
        });
        DB::table('chatgpt_file_admission_guard')->insert(['id' => 1]);

        // No signed URLs, file contents, passwords, Target IDs or user
        // information are retained in this short-lived capacity ledger.
        Schema::create('chatgpt_file_admission_leases', static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('mode', 16);
            $table->unsignedBigInteger('reserved_bytes');
            $table->timestamp('expires_at');
            $table->timestamp('created_at');
            $table->index('expires_at', 'chatgpt_file_leases_expiry');
        });
    }

    public function down(): void
    {
        // Do not silently disable capacity accounting for an in-flight
        // transfer during a rollback; expired orphan leases are reclaimable.
        if (Schema::hasTable('chatgpt_file_admission_leases')
            && DB::table('chatgpt_file_admission_leases')
                ->where('expires_at', '>', now())->exists()) {
            throw new RuntimeException('Wait for active ChatGPT file transfers before reverting admission.');
        }
        Schema::dropIfExists('chatgpt_file_admission_leases');
        Schema::dropIfExists('chatgpt_file_admission_guard');
    }
};
