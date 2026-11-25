<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasColumn('ssh_direct_target_configs', 'route_mode')) {
            // Never guess a path when the existing records disagree.
            $invalid = DB::table('ssh_direct_target_configs as ssh')
                ->join('targets as target', 'target.id', '=', 'ssh.target_record_id')
                ->where(static function ($query): void {
                    $query->whereNotIn('ssh.route_mode', ['direct', 'reverse'])
                        ->orWhere(static fn ($q) => $q->where('ssh.route_mode', 'direct')
                            ->where(static fn ($fields) => $fields->whereNotNull('ssh.reverse_listener_port')->orWhereNotNull('ssh.reverse_tunnel_identity')))
                        ->orWhere(static fn ($q) => $q->where('ssh.route_mode', 'reverse')
                            ->where(static fn ($fields) => $fields->whereNull('ssh.reverse_listener_port')
                                ->orWhereNull('ssh.reverse_tunnel_identity')->orWhereNotNull('target.relay_record_id')));
                })->exists();
            if ($invalid) {
                throw new RuntimeException('Conflicting stored Target transport paths. Reconcile the existing selection before upgrading.');
            }
        }

        if (Schema::hasColumn('targets', 'relay_binding_revision')) {
            Schema::table('targets', static function (Blueprint $table): void {
                $table->renameColumn('relay_binding_revision', 'transport_revision');
            });
        }
        if (! Schema::hasColumn('targets', 'reverse_listener_port')) {
            Schema::table('targets', static function (Blueprint $table): void {
                $table->unsignedSmallInteger('reverse_listener_port')->nullable();
            });
        }
        if (! Schema::hasColumn('targets', 'reverse_tunnel_identity')) {
            Schema::table('targets', static function (Blueprint $table): void {
                $table->string('reverse_tunnel_identity', 80)->nullable();
            });
        }
        if (! Schema::hasIndex('targets', 'target_reverse_unique_port')) {
            Schema::table('targets', static function (Blueprint $table): void {
                $table->unique('reverse_listener_port', 'target_reverse_unique_port');
            });
        }

        if (Schema::hasColumn('ssh_direct_target_configs', 'route_mode')) {
            DB::transaction(static function (): void {
                DB::table('ssh_direct_target_configs')->where('route_mode', 'reverse')
                    ->select(['id', 'target_record_id', 'reverse_listener_port', 'reverse_tunnel_identity'])
                    ->chunkById(100, static function ($rows): void {
                        foreach ($rows as $row) {
                            DB::table('targets')->where('id', $row->target_record_id)->update([
                                'reverse_listener_port' => $row->reverse_listener_port,
                                'reverse_tunnel_identity' => $row->reverse_tunnel_identity,
                            ]);
                        }
                    });
            });
            if (Schema::hasIndex('ssh_direct_target_configs', 'ssh_reverse_unique_port')) {
                Schema::table('ssh_direct_target_configs', static function (Blueprint $table): void {
                    $table->dropUnique('ssh_reverse_unique_port');
                });
            }
            Schema::table('ssh_direct_target_configs', static function (Blueprint $table): void {
                $table->dropColumn(['route_mode', 'reverse_listener_port', 'reverse_tunnel_identity']);
            });
        }
    }

    public function down(): void
    {
        throw new RuntimeException('Restore the pre-update database and matching application key to roll back Target transport conversion.');
    }
};
