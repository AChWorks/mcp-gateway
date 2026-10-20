<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', static function (Blueprint $table): void {
            $table->boolean('ai_access_enabled')->default(false);
        });

        // The only account on the single existing installation is Owner.
        // Keep its current AI connection available; future accounts are opt-in.
        DB::table('users')->where('role', 'owner')->update(['ai_access_enabled' => true]);
    }

    public function down(): void
    {
        Schema::table('users', static function (Blueprint $table): void {
            $table->dropColumn('ai_access_enabled');
        });
    }
};
