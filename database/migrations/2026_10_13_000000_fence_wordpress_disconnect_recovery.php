<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('wp_ai_bridge_target_configs', static function (Blueprint $table): void {
            // Exact metadata evidence, independent of OAuth or other Target
            // success timestamps. Legacy data remains unknown until rechecked.
            $table->timestamp('metadata_checked_at', 6)->nullable();
            $table->boolean('metadata_reachable')->nullable();
        });

        Schema::table('wp_ai_bridge_revocation_intents', static function (Blueprint $table): void {
            // Existing intents have no dispatch/acknowledgment proof. They
            // must remain blocked until explicit WordPress-side reconciliation.
            $table->string('phase', 24)->default('legacy_unknown');
            $table->foreignUlid('credential_id')->nullable();
            $table->unsignedBigInteger('generation')->nullable();
            $table->unsignedTinyInteger('token_total')->nullable();
            $table->unsignedTinyInteger('token_confirmed')->default(0);
        });
    }

    public function down(): void
    {
        // Older runtimes replay remote revoke calls without a durable ledger.
        // Downgrading with ANY outstanding intent loses this safety boundary.
        if (DB::table('wp_ai_bridge_revocation_intents')->exists()) {
            throw new RuntimeException(
                'Cannot roll back WordPress disconnect fencing while revocation intents remain. Reconcile them first.',
            );
        }

        Schema::table('wp_ai_bridge_revocation_intents', static function (Blueprint $table): void {
            $table->dropColumn(['phase', 'credential_id', 'generation', 'token_total', 'token_confirmed']);
        });
        Schema::table('wp_ai_bridge_target_configs', static function (Blueprint $table): void {
            $table->dropColumn(['metadata_checked_at', 'metadata_reachable']);
        });
    }
};
