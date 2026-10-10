<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ssh_direct_target_configs', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->unique()->constrained('targets')->cascadeOnDelete();
            $table->string('host', 253);
            $table->unsignedSmallInteger('port');
            $table->string('username', 128);
            $table->string('auth_method', 32);
            $table->text('pinned_host_key');
            // A one-time attempt fence; only the currently claimed attempt may
            // persist login health, including after a cache lease expires.
            $table->ulid('verification_attempt_id')->nullable();
            $table->string('observed_peer_ip', 45)->nullable();
            $table->timestamp('observed_at', 6)->nullable();
            $table->timestamps();
            $table->index(['host', 'port'], 'ssh_configs_host_port_idx');
            $table->index('observed_peer_ip', 'ssh_configs_observed_ip_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ssh_direct_target_configs');
    }
};
