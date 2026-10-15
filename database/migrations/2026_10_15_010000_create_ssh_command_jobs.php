<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ssh_command_jobs', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->nullable()->constrained('targets')->nullOnDelete();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->char('client_identity_hash', 64);
            $table->uuid('request_id');
            $table->char('script_digest', 64);
            $table->char('target_binding_hash', 64);
            $table->string('unit_mode', 8)->nullable();
            $table->string('status', 32);
            $table->unsignedSmallInteger('runtime_seconds');
            $table->unsignedTinyInteger('exit_code')->nullable();
            $table->string('terminal_reason', 32)->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();

            $table->unique(['target_record_id', 'user_id', 'client_identity_hash', 'request_id'],
                'ssh_jobs_one_launch_per_intent');
            $table->index(['status', 'expires_at'], 'ssh_jobs_retention');
        });
    }

    public function down(): void
    {
        // Every row is a durable no-replay handle and may name still-retained
        // remote scripts/output, including terminal and uncertain jobs.
        // Rollback may proceed ONLY after explicit safe spool reconciliation.
        if (DB::table('ssh_command_jobs')->exists()) {
            throw new RuntimeException('Reconcile and prune every SSH Job before schema rollback.');
        }
        Schema::dropIfExists('ssh_command_jobs');
    }
};
