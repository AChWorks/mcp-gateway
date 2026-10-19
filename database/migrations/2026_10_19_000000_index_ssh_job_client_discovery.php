<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            // Exact principal/client/original-binding predicates before
            // descending ULID keyset pagination; no all-Jobs table scan.
            $table->index(
                ['user_id', 'target_record_id', 'client_identity_hash', 'target_binding_hash', 'id'],
                'ssh_jobs_client_discovery',
            );
        });
    }

    public function down(): void
    {
        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            $table->dropIndex('ssh_jobs_client_discovery');
        });
    }
};
