<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('targets', static function (Blueprint $table): void {
            // Advisory Target metadata; no new access or execution policy.
            $table->text('ai_guidance')->nullable();
        });
    }

    public function down(): void
    {
        // Never silently discard operator-authored guidance on rollback.
        if (DB::table('targets')->whereNotNull('ai_guidance')->exists()) {
            throw new RuntimeException('Clear Target AI guidance explicitly before dropping its column.');
        }

        Schema::table('targets', static function (Blueprint $table): void {
            $table->dropColumn('ai_guidance');
        });
    }
};
