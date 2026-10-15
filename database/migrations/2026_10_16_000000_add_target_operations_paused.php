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
            // Separate from connection and existing Target/ACL identities.
            $table->boolean('operations_paused')->default(false);
        });
    }

    public function down(): void
    {
        // An older runtime cannot enforce a paused Target. Refuse an
        // accidental fail-open rollback while any Target remains paused.
        if (DB::table('targets')->where('operations_paused', true)->exists()) {
            throw new RuntimeException('Resume or explicitly reconcile paused Targets before removing their operational gate.');
        }

        Schema::table('targets', static function (Blueprint $table): void {
            $table->dropColumn('operations_paused');
        });
    }
};
