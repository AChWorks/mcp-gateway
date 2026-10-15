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
            // Independent immutable snapshots outlive FK nullOnDelete and
            // Target/config rotation. No private credentials/scripts retained.
            $table->unsignedBigInteger('original_user_id')->nullable();
            $table->ulid('original_target_record_id')->nullable();
            $table->string('original_target_id', 64)->nullable();
            $table->string('original_host', 253)->nullable();
            $table->unsignedSmallInteger('original_port')->nullable();
            $table->string('original_os_username', 128)->nullable();
            $table->string('original_auth_method', 32)->nullable();
            $table->char('original_host_key_digest', 64)->nullable();
            $table->index(['user_id', 'status', 'admission_expires_at'], 'ssh_jobs_active_lease');
        });

        // Preserve historical journal identity. Existing ambiguous launches
        // receive a conservative bounded admission lease; NULL is treated
        // as still admitted in the runtime until migration completes.
        DB::table('ssh_command_jobs')->select([
            'id', 'created_at', 'runtime_seconds',
            'target_record_id', 'user_id', 'target_binding_hash',
        ])
            ->orderBy('id')->chunkById(100, static function ($rows): void {
                foreach ($rows as $row) {
                    $deadline = Carbon::parse((string) $row->created_at)
                        ->addSeconds((int) $row->runtime_seconds + 120 + 600);
                    $snapshot = [
                        'admission_expires_at' => $deadline,
                        'original_user_id' => $row->user_id,
                        'original_target_record_id' => $row->target_record_id,
                    ];
                    if ($row->target_record_id !== null) {
                        $target = DB::table('targets')->where('id', $row->target_record_id)->first();
                        $config = DB::table('ssh_direct_target_configs')
                            ->where('target_record_id', $row->target_record_id)->first();
                        if ($target !== null && $config !== null) {
                            $originalBinding = hash('sha256', implode("\0", [
                                (string) $row->target_record_id, (string) $target->target_id,
                                (string) $config->host, (string) $config->port,
                                (string) $config->username, (string) $config->auth_method,
                                (string) $config->pinned_host_key,
                            ]));
                            // A rotated/rebound Target must NOT be backfilled
                            // as though its new endpoint were the old Job host.
                            if (hash_equals((string) $row->target_binding_hash, $originalBinding)) {
                                $snapshot += [
                                    'original_target_id' => $target->target_id,
                                    'original_host' => $config->host,
                                    'original_port' => $config->port,
                                    'original_os_username' => $config->username,
                                    'original_auth_method' => $config->auth_method,
                                    'original_host_key_digest' => hash('sha256', $config->pinned_host_key),
                                ];
                            }
                        }
                    }
                    DB::table('ssh_command_jobs')->where('id', $row->id)->update($snapshot);
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
                'original_user_id', 'original_target_record_id',
                'original_target_id', 'original_host', 'original_port',
                'original_os_username', 'original_auth_method',
                'original_host_key_digest',
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
