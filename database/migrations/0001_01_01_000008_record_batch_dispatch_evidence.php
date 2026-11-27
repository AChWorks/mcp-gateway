<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Each addition is independently restartable if a database DDL
        // commit succeeds but migration recording is interrupted.
        if (! Schema::hasColumn('target_batch_items', 'effect_admitted')) {
            Schema::table('target_batch_items', static function (Blueprint $table): void {
                // NULL is historical evidence without a dispatch marker, NOT
                // proof of no effect. New claims explicitly start at false.
                $table->boolean('effect_admitted')->nullable();
            });
        }
        if (! Schema::hasColumn('target_batch_items', 'late_observation_ciphertext')) {
            Schema::table('target_batch_items', static function (Blueprint $table): void {
                $table->longText('late_observation_ciphertext')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (DB::table('target_batch_items')->whereNotNull('effect_admitted')
            ->orWhereNotNull('late_observation_ciphertext')->exists()) {
            throw new RuntimeException('Restore the pre-update database to roll back retained Batch dispatch evidence.');
        }
        Schema::table('target_batch_items', static function (Blueprint $table): void {
            $table->dropColumn(['effect_admitted', 'late_observation_ciphertext']);
        });
    }
};
