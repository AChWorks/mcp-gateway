<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            // Independent nullable typed columns preserve previous releases'
            // two-key JSON format and permit Owner-controlled limits.
            $table->unsignedSmallInteger('ssh_job_max_active_per_user')->nullable();
            $table->unsignedInteger('ssh_job_max_runtime_seconds')->nullable();
            $table->unsignedSmallInteger('ssh_job_retention_hours')->nullable();
            $table->unsignedSmallInteger('ssh_job_preparing_grace_seconds')->nullable();
            $table->unsignedSmallInteger('ssh_job_reconcile_grace_seconds')->nullable();
        });

        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            // Older unpublished candidate installs used unsignedSmallInteger.
            $table->unsignedInteger('runtime_seconds')->change();
            $table->timestamp('admission_expires_at')->nullable();
            $table->timestamp('operator_attested_at')->nullable();
            $table->string('operator_attested_reason', 240)->nullable();
            $table->unsignedInteger('operator_attested_uid')->nullable();
            $table->index(['user_id', 'status', 'admission_expires_at'], 'ssh_jobs_active_lease');
        });

        // Preserve historical journal identity. Existing ambiguous launches
        // receive a conservative bounded admission lease; NULL is treated
        // as still admitted in the runtime until migration completes.
        DB::table('ssh_command_jobs')->select(['id', 'created_at', 'runtime_seconds'])
            ->orderBy('id')->chunkById(100, static function ($rows): void {
                foreach ($rows as $row) {
                    $deadline = Carbon::parse((string) $row->created_at)
                        ->addSeconds((int) $row->runtime_seconds + 120 + 600);
                    DB::table('ssh_command_jobs')->where('id', $row->id)
                        ->update(['admission_expires_at' => $deadline]);
                }
            });
    }

    public function down(): void
    {
        // Undoing the lease schema while any durable Job identity exists can
        // silently revive permanent starvation. Never discard safety data.
        if (DB::table('ssh_command_jobs')->exists()) {
            throw new RuntimeException('Reconcile and prune every SSH Job before reverting lifecycle policy.');
        }

        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            $table->dropIndex('ssh_jobs_active_lease');
            $table->dropColumn([
                'admission_expires_at', 'operator_attested_at',
                'operator_attested_reason', 'operator_attested_uid',
            ]);
            $table->unsignedSmallInteger('runtime_seconds')->change();
        });
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn([
                'ssh_job_max_active_per_user', 'ssh_job_max_runtime_seconds',
                'ssh_job_retention_hours', 'ssh_job_preparing_grace_seconds',
                'ssh_job_reconcile_grace_seconds',
            ]);
        });
    }
};
