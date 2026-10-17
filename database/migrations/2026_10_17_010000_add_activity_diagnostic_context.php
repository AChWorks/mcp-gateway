<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Store selectively redacted observed error details on the existing Activity row.
        // Correlation ID is already indexed; no second diagnostic datastore.
        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->json('diagnostic_context')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->dropColumn('diagnostic_context');
        });
    }
};
