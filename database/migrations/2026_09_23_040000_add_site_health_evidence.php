<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('sites', function (Blueprint $table): void {
            $table->timestamp('last_tested_at', 6)->nullable()->change();
        });

        Schema::table('sites', function (Blueprint $table): void {
            $table->timestamp('last_success_at', 6)->nullable();
            $table->timestamp('last_failure_at', 6)->nullable();
            $table->string('last_failure_code', 64)->nullable();
            $table->index(
                ['connection_state', 'last_success_at'],
                'sites_state_last_success_at_index',
            );
        });
    }

    public function down(): void
    {
        Schema::table('sites', function (Blueprint $table): void {
            $table->dropIndex('sites_state_last_success_at_index');
            $table->dropColumn(['last_success_at', 'last_failure_at', 'last_failure_code']);
        });

        Schema::table('sites', function (Blueprint $table): void {
            $table->timestamp('last_tested_at')->nullable()->change();
        });
    }
};
