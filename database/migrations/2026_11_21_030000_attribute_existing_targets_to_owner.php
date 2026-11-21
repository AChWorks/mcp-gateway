<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Preflight before DDL: MySQL/MariaDB cannot roll back schema changes
        // if this is an unexpected legacy installation without an Owner.
        $hasLegacyTargets = DB::table('targets')->exists();
        $ownerId = $hasLegacyTargets
            ? DB::table('users')->where('role', 'owner')->orderBy('id')->value('id')
            : null;
        if ($hasLegacyTargets && $ownerId === null) {
            throw new RuntimeException('Existing Targets require an Owner before creator attribution.');
        }

        Schema::table('users', static function (Blueprint $table): void {
            $table->boolean('self_created_target_access')->default(false);
        });
        Schema::table('targets', static function (Blueprint $table): void {
            $table->foreignId('created_by_user_id')->nullable()
                ->constrained('users')->nullOnDelete();
        });

        // Existing fleet is owned by the original installation Owner, not by
        // historical guessed operators. No direct grants are materialized:
        // Owners already have unrestricted Target authority.
        if ($hasLegacyTargets) {
            DB::table('targets')->whereNull('created_by_user_id')->update(['created_by_user_id' => $ownerId]);
        }
    }

    public function down(): void
    {
        Schema::table('targets', static function (Blueprint $table): void {
            $table->dropConstrainedForeignId('created_by_user_id');
        });
        Schema::table('users', static function (Blueprint $table): void {
            $table->dropColumn('self_created_target_access');
        });
    }
};
