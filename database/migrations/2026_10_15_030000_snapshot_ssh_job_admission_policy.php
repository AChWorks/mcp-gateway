<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            // Immutable start-specific policy. Owner settings changes apply to
            // NEW Jobs only; neither a delayed start nor recovery may recompute
            // another Job's deadlines from mutable current settings.
            $table->timestamp('preparing_expires_at')->nullable();
            $table->unsignedSmallInteger('reconcile_grace_seconds')->nullable();
        });

        // Preserve older prerelease records without guessing their historical
        // settings. The maximum supported prior values are conservative
        // snapshots for uncertain/migrating Jobs, not permission to relaunch.
        // Increase, never decrease, an already held admission deadline.
        DB::table('ssh_command_jobs')
            ->select(['id', 'created_at', 'runtime_seconds', 'admission_expires_at'])
            ->orderBy('id')
            ->chunkById(100, static function ($rows): void {
                foreach ($rows as $row) {
                    $created = Carbon::parse((string) $row->created_at);
                    $preparing = $created->copy()->addSeconds(600);
                    $conservativeLease = $created->copy()->addSeconds(
                        600 + 360 + 90 + (int) $row->runtime_seconds + 3600,
                    );
                    $existing = $row->admission_expires_at === null
                        ? null : (string) $row->admission_expires_at;
                    DB::table('ssh_command_jobs')->where('id', $row->id)->update([
                        'preparing_expires_at' => $preparing,
                        'reconcile_grace_seconds' => 3600,
                        'admission_expires_at' => $existing === null
                            ? $conservativeLease->toDateTimeString()
                            : max($existing, $conservativeLease->toDateTimeString()),
                    ]);
                }
            });
    }

    public function down(): void
    {
        // Retiring these snapshots while Job identities remain would allow
        // Owner policy drift to change their start/admission guarantees.
        if (DB::table('ssh_command_jobs')->exists()) {
            throw new RuntimeException('Reconcile and prune every SSH Job before reverting admission policy snapshots.');
        }

        Schema::table('ssh_command_jobs', static function (Blueprint $table): void {
            $table->dropColumn(['preparing_expires_at', 'reconcile_grace_seconds']);
        });
    }
};
