<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('target_credentials', 'authority_revision')) {
            Schema::table('target_credentials', static function (Blueprint $table): void {
                $table->unsignedBigInteger('authority_revision')->default(0);
            });
        }

        // A previously committed local disconnect has already closed ordinary
        // new-work authority. Preserve the exact intent and encrypted material,
        // including legacy intents which predate credential IDs. No remote
        // revocation is asserted here. Restarting the migration is idempotent.
        DB::table('target_credentials')->where('connector_type', 'wp_ai_bridge')
            ->where('authority_revision', 0)
            ->whereExists(static function ($query): void {
                $query->selectRaw('1')->from('wp_ai_bridge_revocation_intents')
                    ->whereColumn('target_record_id', 'target_credentials.target_record_id')
                    ->where('kind', 'disconnect');
            })->update(['authority_revision' => 1]);
    }

    public function down(): void
    {
        throw new RuntimeException('Restore the pre-update database to roll back credential authority revisions without reviving old grants.');
    }
};
