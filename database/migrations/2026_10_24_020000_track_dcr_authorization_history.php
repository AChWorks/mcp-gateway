<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_dcr_clients', static function (Blueprint $table): void {
            // This is a durable monotonic witness of a successful consent.
            // It does not reference a user/grant row that can cascade-delete.
            $table->timestamp('ever_authorized_at')->nullable();
            // Old registrations have unknown past authorization state:
            // preserve them rather than assuming an absent grant means never used.
            $table->boolean('auto_retirement_eligible')->default(false);
            $table->index(
                ['retired_at', 'auto_retirement_eligible', 'created_at'],
                'oauth_dcr_clients_reclaim',
            );
        });

        // A historical grant that still exists, even if revoked, is positive
        // evidence that this identity has previously gained consent.
        // A missing historical grant is NOT proof that consent never occurred:
        // users may have been deleted with ON DELETE CASCADE.
        DB::table('oauth_dcr_clients')
            ->whereIn('client_id', DB::table('oauth_authorizations')->select('client_id'))
            ->update(['ever_authorized_at' => now()]);
    }

    public function down(): void
    {
        // Discarding this witness could let a future capacity-pressure request
        // permanently retire an identity whose user/grants were deleted.
        if (DB::table('oauth_dcr_clients')->exists()) {
            throw new RuntimeException('Cannot discard durable DCR consent history while registrations exist.');
        }

        Schema::table('oauth_dcr_clients', static function (Blueprint $table): void {
            $table->dropIndex('oauth_dcr_clients_reclaim');
            $table->dropColumn(['ever_authorized_at', 'auto_retirement_eligible']);
        });
    }
};
