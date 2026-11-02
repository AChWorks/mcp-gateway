<?php

use App\Application\Targets\SshManagedReverseAuthorizedKeys;
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
            // Prevent admission while configuration and SSHD key file diverge.
            $table->boolean('publication_pending')->default(false);
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
            // Durable publication receipt survives PHP/file/DB partial failures.
            $table->boolean('publication_pending')->default(false);
            $table->timestamps();
        });

        // Never recycle a listener that may still be occupied by a remote
        // reverse forward from an earlier enrollment generation.
        Schema::create('ssh_reverse_managed_retired_ports', static function (Blueprint $table): void {
            $table->unsignedSmallInteger('listener_port')->primary();
            $table->string('target_id', 64);
            $table->timestamp('retired_at');
        });
    }

    public function down(): void
    {
        // Serialize the final decision and table drops against live Gateway
        // claim, revocation, settings and authorized_keys publication workers.
        $rollback = static function (): void {
            // A revoked database row alone does not prove that the external SSHD
            // reader was updated. These tables are the durable recovery receipt.
            if (DB::table('ssh_reverse_managed_enrollments')->where('state', '!=', 'revoked')->exists()) {
                throw new RuntimeException('Revoke all managed Reverse SSH enrollments before rollback.');
            }
            if (DB::table('ssh_reverse_managed_enrollments')->where('publication_pending', true)->exists()) {
                throw new RuntimeException('Reconcile pending managed Reverse SSH key publication before rollback.');
            }

            $gateway = DB::table('ssh_reverse_gateway_settings')->where('id', 1)->first();
            if ($gateway !== null) {
                if ($gateway->enabled || $gateway->publication_pending) {
                    throw new RuntimeException('Disable and reconcile Gateway Reverse SSH configuration before rollback.');
                }
                if (! app(SshManagedReverseAuthorizedKeys::class)->isReconciled()) {
                    throw new RuntimeException('Verify that the restricted SSH key reader is empty and reconciled before rollback.');
                }
            } elseif (DB::table('ssh_reverse_managed_enrollments')->exists()) {
                throw new RuntimeException('Managed enrollments lack the Gateway publication receipt; refuse rollback.');
            }

            // Retired listeners may still be owned by a superseded Target's -R
            // session. Never discard their collision quarantine silently.
            if (DB::table('ssh_reverse_managed_retired_ports')->exists()) {
                throw new RuntimeException('Reconcile retired Reverse SSH listener history before rollback.');
            }

            Schema::dropIfExists('ssh_reverse_managed_retired_ports');
            Schema::dropIfExists('ssh_reverse_managed_enrollments');
            Schema::dropIfExists('ssh_reverse_gateway_settings');
        };
        if (DB::table('ssh_reverse_gateway_settings')->exists()) {
            app(SshManagedReverseAuthorizedKeys::class)->withPolicyLock($rollback);
        } else {
            // Fresh, never-configured installs have no external key writer.
            $rollback();
        }
    }
};
