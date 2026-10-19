<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('operational_settings', static function (Blueprint $table): void {
            // Previously unsignedTinyInteger: cannot represent 360s or 512 KiB.
            // Width changes retain existing values on SQLite and MariaDB.
            $table->unsignedSmallInteger('ssh_command_timeout_seconds')->nullable()->change();
            $table->unsignedSmallInteger('ssh_command_max_kib')->nullable()->change();
            $table->unsignedSmallInteger('ssh_job_max_script_kib')->nullable()->change();

            $table->unsignedSmallInteger('ssh_command_stdout_kib')->nullable();
            $table->unsignedSmallInteger('ssh_command_stderr_kib')->nullable();
            $table->unsignedSmallInteger('ssh_job_output_window_kib')->nullable();
            $table->unsignedSmallInteger('ssh_file_read_window_kib')->nullable();
            $table->unsignedSmallInteger('ssh_file_write_window_kib')->nullable();
            $table->unsignedSmallInteger('ssh_file_list_name_kib')->nullable();
        });
    }

    public function down(): void
    {
        // Never silently discard accepted Owner overrides or downgrade below
        // values the old application can represent/interpret.
        $row = DB::table('operational_settings')->where('id', 1)->first();
        if ($row !== null) {
            foreach ([
                'ssh_command_timeout_seconds' => 30,
                'ssh_command_max_kib' => 64,
                'ssh_job_max_script_kib' => 64,
            ] as $column => $legacyMaximum) {
                if ($row->{$column} !== null && (int) $row->{$column} > $legacyMaximum) {
                    throw new RuntimeException('Refusing lossy rollback of expanded SSH resource settings.');
                }
            }
            foreach ([
                'ssh_command_stdout_kib', 'ssh_command_stderr_kib',
                'ssh_job_output_window_kib', 'ssh_file_read_window_kib',
                'ssh_file_write_window_kib', 'ssh_file_list_name_kib',
            ] as $column) {
                if ($row->{$column} !== null) {
                    throw new RuntimeException('Reset newly configured SSH budgets before rollback.');
                }
            }
        }

        Schema::table('operational_settings', static function (Blueprint $table): void {
            $table->dropColumn([
                'ssh_command_stdout_kib', 'ssh_command_stderr_kib',
                'ssh_job_output_window_kib', 'ssh_file_read_window_kib',
                'ssh_file_write_window_kib', 'ssh_file_list_name_kib',
            ]);
            $table->unsignedTinyInteger('ssh_command_timeout_seconds')->nullable()->change();
            $table->unsignedTinyInteger('ssh_command_max_kib')->nullable()->change();
            $table->unsignedTinyInteger('ssh_job_max_script_kib')->nullable()->change();
        });
    }
};
