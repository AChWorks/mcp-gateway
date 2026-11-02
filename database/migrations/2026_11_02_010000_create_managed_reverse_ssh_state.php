<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ssh_reverse_gateway_settings', static function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
            $table->boolean('enabled')->default(false);
            $table->string('control_host', 253);
            $table->unsignedSmallInteger('control_port');
            $table->string('control_user', 64);
            $table->string('control_host_key', 4096);
            $table->unsignedBigInteger('revision')->default(0);
            $table->timestamps();
        });

        Schema::create('ssh_reverse_managed_enrollments', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('target_id', 64)->unique();
            $table->foreignUlid('target_record_id')->unique()->constrained('targets')->cascadeOnDelete();
            $table->unsignedSmallInteger('listener_port')->unique();
            $table->string('tunnel_identity', 80)->unique();
            // Only public keys. Private credentials belong to the encrypted Target vault.
            $table->text('control_public_key')->nullable();
            $table->char('control_key_hash', 64)->nullable()->unique();
            $table->text('login_public_key');
            $table->char('token_hash', 64)->nullable();
            $table->timestamp('token_expires_at')->nullable();
            $table->timestamp('claimed_at')->nullable();
            $table->timestamp('activated_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->string('state', 16)->default('pending');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        if (DB::table('ssh_reverse_managed_enrollments')->where('state', '!=', 'revoked')->exists()) {
            throw new RuntimeException('Revoke and retire managed Reverse SSH enrollments before rollback.');
        }
        Schema::dropIfExists('ssh_reverse_managed_enrollments');
        Schema::dropIfExists('ssh_reverse_gateway_settings');
    }
};
