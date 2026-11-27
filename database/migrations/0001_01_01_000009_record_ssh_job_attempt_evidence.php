<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('ssh_command_jobs', 'original_peer_fingerprint')) {
            Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
                $table->char('original_peer_fingerprint', 64)->nullable();
            });
        }
        if (! Schema::hasColumn('ssh_command_jobs', 'launch_admitted')) {
            Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
                // Historical NULL means no recorded launch evidence, not unsent.
                $table->boolean('launch_admitted')->nullable();
            });
        }
        if (! Schema::hasColumn('ssh_command_jobs', 'launch_observation_ciphertext')) {
            Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
                $table->longText('launch_observation_ciphertext')->nullable();
            });
        }
        // History is scoped by the immutable Target record, not its
        // mutable transport binding. Preserve efficient keyset discovery.
        if (! Schema::hasIndex('ssh_command_jobs', 'ssh_jobs_history_scope')) {
            Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
                $table->index(['user_id', 'target_record_id', 'client_identity_hash', 'id'], 'ssh_jobs_history_scope');
            });
        }
        if (Schema::hasIndex('ssh_command_jobs', 'ssh_jobs_client_discovery')) {
            Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
                $table->dropIndex('ssh_jobs_client_discovery');
            });
        }
    }

    public function down(): void
    {
        if (DB::table('ssh_command_jobs')->whereNotNull('original_peer_fingerprint')
            ->orWhereNotNull('launch_admitted')->orWhereNotNull('launch_observation_ciphertext')->exists()) {
            throw new RuntimeException('Restore the pre-update database to roll back retained SSH Job evidence.');
        }
        if (! Schema::hasIndex('ssh_command_jobs', 'ssh_jobs_client_discovery')) {
            Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
                $table->index(['user_id', 'target_record_id', 'client_identity_hash', 'target_binding_hash', 'id'], 'ssh_jobs_client_discovery');
            });
        }
        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            $table->dropIndex('ssh_jobs_history_scope');
            $table->dropColumn(['original_peer_fingerprint', 'launch_admitted', 'launch_observation_ciphertext']);
        });
    }
};
