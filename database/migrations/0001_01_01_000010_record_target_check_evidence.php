<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('targets', 'last_error_check_kind')) {
            Schema::table('targets', static function (Blueprint $table): void {
                $table->string('last_error_check_kind', 32)->nullable();
            });
        }
        if (! Schema::hasTable('target_check_evidence')) {
            Schema::create('target_check_evidence', static function (Blueprint $table): void {
                $table->foreignUlid('target_record_id')->constrained('targets')->cascadeOnDelete();
                $table->string('kind', 32);
                $table->unsignedBigInteger('transport_revision')->nullable();
                $table->ulid('attempt_id')->nullable();
                $table->dateTime('observed_at', 6)->nullable();
                $table->string('error_code', 64)->nullable();
                $table->dateTime('last_failure_at', 6)->nullable();
                $table->string('last_failure_code', 64)->nullable();
                $table->primary(['target_record_id', 'kind']);
            });
        }
        // Import only observations whose legacy fields establish the same
        // current generation. Ambiguous older records remain diagnostic history.
        DB::table('targets')->where('connector_type', 'ssh_direct')
            ->whereNotNull('last_tested_at')->whereIn('connection_state', ['connected', 'pending', 'error'])
            ->orderBy('id')->chunkById(200, static function ($targets): void {
                foreach ($targets as $target) {
                    if ($target->last_error_code !== null || $target->connection_state === 'connected') {
                        DB::table('target_check_evidence')->insertOrIgnore([
                            'target_record_id' => $target->id, 'kind' => 'ssh_login',
                            'transport_revision' => $target->transport_revision,
                            'observed_at' => $target->last_tested_at, 'error_code' => $target->last_error_code,
                            'last_failure_at' => $target->last_failure_at,
                            'last_failure_code' => $target->last_failure_code,
                        ]);
                    }
                }
            });
        DB::table('targets')->where('connector_type', 'arvancloud')->where('connection_state', 'connected')
            ->whereNotNull('last_tested_at')->orderBy('id')->chunkById(200, static function ($targets): void {
                foreach ($targets as $target) {
                    DB::table('target_check_evidence')->insertOrIgnore([
                        'target_record_id' => $target->id, 'kind' => 'arvan_auth',
                        'transport_revision' => $target->transport_revision, 'observed_at' => $target->last_tested_at,
                    ]);
                }
            });
        DB::table('targets')->join('wp_ai_bridge_target_configs as config', 'config.target_record_id', '=', 'targets.id')
            ->whereNotNull('config.metadata_checked_at')->whereNotNull('config.metadata_reachable')
            ->select(['targets.id', 'targets.transport_revision', 'targets.last_tested_at', 'targets.last_failure_at',
                'targets.last_failure_code', 'targets.last_error_code', 'targets.connection_state',
                'config.metadata_checked_at', 'config.metadata_reachable'])
            ->orderBy('targets.id')->chunkById(200, static function ($targets): void {
                DB::transaction(static function () use ($targets): void {
                    foreach ($targets as $target) {
                        // A newer legacy explicit failed metadata check left the old
                        // successful config timestamp unchanged. Only exact,
                        // attributable observations can be current.
                        $observed = $target->metadata_checked_at;
                        $error = $target->metadata_reachable ? null : 'metadata_check_failed';
                        if ($target->last_tested_at !== null && $target->last_failure_at === $target->last_tested_at
                            && $target->last_failure_at > $observed && $target->last_failure_code !== null) {
                            $observed = $target->last_tested_at;
                            $error = $target->last_failure_code;
                        }
                        $owned = $target->connection_state === 'error' && ! $target->metadata_reachable
                            && $target->last_error_code !== null && $target->last_error_code === $target->last_failure_code
                            && $target->last_tested_at !== null && $target->last_failure_at !== null
                            && $target->metadata_checked_at <= $target->last_failure_at
                            && $target->last_failure_at <= $target->last_tested_at
                            && ! DB::table('target_credentials')->where('target_record_id', $target->id)->exists()
                            && ! DB::table('wp_ai_bridge_oauth_flows')->where('target_record_id', $target->id)->exists()
                            && ! DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $target->id)->exists()
                            && ! DB::table('wp_ai_bridge_revocation_intents')->where('target_record_id', $target->id)->exists();
                        if ($owned) {
                            // Legacy discovery wrote config, lifecycle failure, then
                            // last_tested_at in that order under the same row lock.
                            // The Error state without a grant/intent distinguishes
                            // this from callback and credential lifecycle failures.
                            $observed = $target->last_tested_at;
                            $error = $target->last_error_code;
                        }
                        $current = $target->last_tested_at === $observed
                            || ((int) $target->transport_revision === 0 && $target->last_tested_at === null);
                        $inserted = DB::table('target_check_evidence')->insertOrIgnore([
                            'target_record_id' => $target->id, 'kind' => 'wordpress_metadata',
                            'transport_revision' => $current ? $target->transport_revision : null,
                            'observed_at' => $observed, 'error_code' => $error,
                            'last_failure_at' => $error === null ? null : $observed,
                            'last_failure_code' => $error,
                        ]);
                        if ($owned && $inserted === 1) {
                            DB::table('targets')->where('id', $target->id)->whereNull('last_error_check_kind')
                                ->update(['last_error_check_kind' => 'wordpress_metadata']);
                        }
                    }
                });
            }, 'targets.id', 'id');
    }

    public function down(): void
    {
        if (DB::table('target_check_evidence')->exists() || DB::table('targets')->whereNotNull('last_error_check_kind')->exists()) {
            throw new RuntimeException('Restore the pre-update database to roll back Target check evidence.');
        }
        Schema::dropIfExists('target_check_evidence');
        Schema::table('targets', static function (Blueprint $table): void {
            $table->dropColumn('last_error_check_kind');
        });
    }
};
