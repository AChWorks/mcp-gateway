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
        // Removing the route columns from an active Reverse Target strands
        // route-bound encrypted secrets. Retained Job rows (including unknown
        // results) may still reference a prior Reverse binding after rotation.
        // Require explicit migration retirement/reconciliation, never silently
        // reinterpret a Reverse host as a Direct one.
        if (DB::table('ssh_direct_target_configs')->where('route_mode', 'reverse')->exists()
            || DB::table('ssh_command_jobs')->exists()) {
            throw new RuntimeException('Reconcile all SSH Jobs and rotate all Reverse SSH Targets to Direct before rollback.');
        }
        Schema::table('ssh_direct_target_configs', static function (Blueprint $table): void {
            $table->dropUnique('ssh_reverse_unique_port');
            $table->dropColumn(['route_mode', 'reverse_listener_port', 'reverse_tunnel_identity', 'binding_revision']);
        });
    }
};
