<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('connection_relays', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('relay_id', 64)->unique();
            $table->string('display_name', 160);
            $table->string('control_host', 253);
            $table->unsignedSmallInteger('control_port');
            $table->string('control_user', 128);
            $table->text('control_host_key');
            $table->unsignedSmallInteger('local_socks_port')->unique();
            $table->unsignedInteger('configuration_revision')->default(1);
            $table->unsignedInteger('lifecycle_revision')->default(1);
            $table->boolean('enabled')->default(false);
            $table->timestamps();
        });

        Schema::table('targets', static function (Blueprint $table): void {
            $table->foreignUlid('relay_record_id')->nullable()
                ->constrained('connection_relays')->restrictOnDelete();
            // A->B->A must never revive a retained SSH job. This counter
            // survives unbinding, disable and reconnection.
            $table->unsignedInteger('relay_binding_revision')->default(0);
        });
    }

    public function down(): void
    {
        // Dropping a positive epoch can revive jobs with a historical Direct
        // binding. This operation must never discard monotonic security state.
        if (DB::table('targets')->whereNotNull('relay_record_id')
            ->orWhere('relay_binding_revision', '>', 0)->exists()
            || (Schema::hasTable('ssh_command_jobs') && DB::table('ssh_command_jobs')->exists())) {
            throw new RuntimeException('Connection Relay rollback requires separately reconciled Target bindings and retained Jobs.');
        }
        Schema::table('targets', static function (Blueprint $table): void {
            $table->dropConstrainedForeignId('relay_record_id');
            $table->dropColumn('relay_binding_revision');
        });
        Schema::dropIfExists('connection_relays');
    }
};
