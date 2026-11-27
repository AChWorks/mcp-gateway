<?php

declare(strict_types=1);

use App\Application\Targets\ConnectionRelayAdministration;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** Measure actual transactional route revision + required audit writes, with
 * metadata-only synthetic targets; no claim of thousands of network hosts. */
function measureInstalledRouteFanout(): array
{
    $relay = ConnectionRelay::query()->where('relay_id', 'mixed-native-relay')->sole();
    if ($relay->enabled || DB::table('targets')->where('relay_record_id', $relay->id)->exists()) {
        throw new RuntimeException('Expected disabled, detached disposable Relay.');
    }
    $queries = 0;
    DB::listen(static function () use (&$queries): void {
        $queries++;
    });
    $measurements = [];
    foreach ([100, 1000] as $count) {
        $rows = [];
        $ids = [];
        $now = now();
        for ($i = 0; $i < $count; $i++) {
            $id = (string) Str::ulid();
            $ids[] = $id;
            $rows[] = [
                'id' => $id, 'target_id' => 'fanout-'.$count.'-'.$i,
                'display_name' => 'Synthetic route metadata', 'connector_type' => 'ssh_direct',
                'connection_state' => 'disconnected', 'relay_record_id' => $relay->id,
                'transport_revision' => 1, 'last_tested_at' => $now,
                'created_at' => $now, 'updated_at' => $now,
            ];
        }
        foreach (array_chunk($rows, 100) as $page) {
            DB::table('targets')->insert($page);
        }
        unset($rows);
        $edges = [];
        foreach ([true, false] as $enabled) {
            $relay->refresh();
            $queries = 0;
            memory_reset_peak_usage();
            $baseMemory = memory_get_usage(true);
            $start = hrtime(true);
            $changed = app(ConnectionRelayAdministration::class)->setEnabled(
                $relay, $relay->lifecycle_revision, $enabled,
            );
            $elapsed = round((hrtime(true) - $start) / 1000000, 2);
            if (! $changed) {
                throw new RuntimeException('Expected actual materialized availability edge.');
            }
            $edges[] = ['enabled' => $enabled, 'elapsed_ms' => $elapsed,
                'sql_queries' => $queries, 'peak_php_allocated_bytes' => memory_get_peak_usage(true),
                'incremental_php_allocated_bytes' => memory_get_peak_usage(true) - $baseMemory];
        }
        if (DB::table('targets')->where('relay_record_id', $relay->id)
            ->where('transport_revision', 3)->whereNull('last_tested_at')->count() !== $count
            || DB::table('activity_events')->whereIn('target_record_id', $ids)
                ->whereIn('operation', ['target-relay-enabled', 'target-relay-disabled'])->count() !== 2 * $count) {
            throw new RuntimeException('Route fan-out did not preserve every revision and audit record.');
        }
        $measurements[] = ['bound_metadata_targets' => $count, 'edges' => $edges, 'all_epochs_and_audit_verified' => true];
        foreach (array_chunk($ids, 100) as $page) {
            DB::table('targets')->whereIn('id', $page)->delete();
        }
    }

    return ['scope' => 'metadata-only real MariaDB transaction; no remote hosts/operations',
        'measurements' => $measurements, 'synthetic_targets_removed' => true];
}
