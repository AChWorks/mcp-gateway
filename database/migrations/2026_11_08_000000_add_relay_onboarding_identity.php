<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('connection_relays', static function (Blueprint $table): void {
            $table->text('login_public_key')->nullable();
            $table->longText('login_private_key_encrypted')->nullable();
        });
    }

    public function down(): void
    {
        // Dropping live login keys may strand installed Gateway tunnels.
        // Empty/legacy records can be safely rolled back by a test operator.
        if (DB::table('connection_relays')
            ->whereNotNull('login_private_key_encrypted')->exists()) {
            throw new RuntimeException('Relay onboarding keys require explicit host reconciliation before rollback.');
        }
        Schema::table('connection_relays', static function (Blueprint $table): void {
            $table->dropColumn(['login_public_key', 'login_private_key_encrypted']);
        });
    }
};
