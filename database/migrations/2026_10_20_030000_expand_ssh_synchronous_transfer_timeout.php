<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // The original 0..255 column cannot hold the Owner-selected 3600s.
        // Preserve every existing override on SQLite and MariaDB.
        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->unsignedSmallInteger('ssh_transfer_max_seconds')->nullable()->change();
        });
    }

    public function down(): void
    {
        $row = DB::table('operational_settings')->where('id', 1)->first();
        if ($row !== null && (
            ($row->ssh_transfer_max_seconds !== null && (int) $row->ssh_transfer_max_seconds > 40)
            || ($row->ssh_command_timeout_seconds !== null && (int) $row->ssh_command_timeout_seconds > 360)
        )) {
            throw new RuntimeException('Reset extended SSH synchronous deadlines before rollback.');
        }

        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->unsignedTinyInteger('ssh_transfer_max_seconds')->nullable()->change();
        });
    }
};
