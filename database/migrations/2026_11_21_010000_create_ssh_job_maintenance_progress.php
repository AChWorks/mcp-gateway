<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ssh_job_maintenance_progress', static function (Blueprint $table): void {
            $table->string('operation', 24)->primary();
            $table->timestamp('last_expires_at')->nullable();
            $table->ulid('last_id')->nullable();
            $table->timestamps();
        });
        DB::table('ssh_job_maintenance_progress')->insert(array_map(
            static fn (string $operation): array => [
                'operation' => $operation, 'last_expires_at' => null, 'last_id' => null,
                'created_at' => now(), 'updated_at' => now(),
            ], ['prune', 'reconcile'],
        ));
    }

    public function down(): void
    {
        Schema::dropIfExists('ssh_job_maintenance_progress');
    }
};
