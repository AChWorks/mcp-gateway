<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ssh_direct_target_configs', static function (Blueprint $table): void {
            $table->string('route_mode', 16)->default('direct');
            $table->unsignedSmallInteger('reverse_listener_port')->nullable()->unique('ssh_reverse_unique_port');
            $table->string('reverse_tunnel_identity', 80)->nullable();
            // Monotonic: once any SSH trust/route binding changes, restoring
            // its old coordinates must not reactivate a historical retained Job.
            $table->unsignedInteger('binding_revision')->default(0);
        });
    }

    public function down(): void
    {
        // Both active Reverse routes AND reconfigured Direct routes can have
        // credentials sealed to a positive binding revision. Dropping that
        // revision would make the legitimate ciphertext unreadable by the
        // legacy Direct binding, even if no Reverse route or Job remains.
        // Retained Jobs also require explicit no-replay reconciliation.
        // Refuse BEFORE dropping any columns; never silently reset revisions
        // or attempt an unverified secret conversion during schema rollback.
        if (DB::table('ssh_direct_target_configs')
            ->where('route_mode', 'reverse')
            ->orWhere('binding_revision', '>', 0)
            ->exists() || DB::table('ssh_command_jobs')->exists()) {
            throw new RuntimeException(
                'SSH route schema rollback refused: active Reverse routes, positive SSH binding revisions, '
                .'or retained SSH Jobs remain. Reconcile Jobs and routes; keep the current schema for '
                .'revision-bound encrypted credentials until an independently verified downgrade '
                .'conversion and recovery plan is available.'
            );
        }
        Schema::table('ssh_direct_target_configs', static function (Blueprint $table): void {
            $table->dropUnique('ssh_reverse_unique_port');
            $table->dropColumn(['route_mode', 'reverse_listener_port', 'reverse_tunnel_identity', 'binding_revision']);
        });
    }
};
