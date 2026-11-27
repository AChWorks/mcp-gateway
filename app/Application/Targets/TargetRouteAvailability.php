<?php

namespace App\Application\Targets;

use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;

/**
 * Local administrative route evidence, not network liveness or admission.
 * The same bounded SQL predicate drives review and its explanation.
 */
final readonly class TargetRouteAvailability
{
    public function __construct(private SshReverseRoutePolicy $reverse) {}

    public function unavailable(): Builder
    {
        $allowed = $this->reverse->approvedRoutes();

        return DB::table('targets')->select('targets.id')->where(function (Builder $query) use ($allowed): void {
            $query->where(function (Builder $relay): void {
                $relay->whereNotNull('targets.relay_record_id')->whereNotExists(
                    DB::table('connection_relays')->selectRaw('1')
                        ->whereColumn('connection_relays.id', 'targets.relay_record_id')->where('enabled', true)
                );
            })->orWhere(function (Builder $reverse) use ($allowed): void {
                $reverse->whereNotNull('targets.reverse_listener_port');
                if ($allowed === null) {
                    return;
                }
                // Exact manual ownership or an active/pending matching managed
                // enrollment. Ordinary initial pending setup is not a failure.
                $manual = DB::table('ssh_reverse_managed_enrollments')->selectRaw('1')
                    ->whereColumn('target_id', 'targets.target_id');
                $reverse->whereNot(function (Builder $available) use ($allowed, $manual): void {
                    $available->where(function (Builder $managed) use ($allowed): void {
                        $managed->whereNotIn('targets.target_id', array_keys($allowed))
                            ->whereNotIn('targets.reverse_listener_port', array_column($allowed, 'port'))
                            ->whereExists(DB::table('ssh_reverse_gateway_settings')->selectRaw('1')
                                ->where('id', 1)->where('enabled', true)->where('publication_pending', false))
                            ->whereExists(DB::table('ssh_reverse_managed_enrollments')->selectRaw('1')
                                ->whereColumn('target_record_id', 'targets.id')
                                ->whereColumn('target_id', 'targets.target_id')
                                ->whereColumn('listener_port', 'targets.reverse_listener_port')
                                ->whereColumn('tunnel_identity', 'targets.reverse_tunnel_identity')
                                ->whereNull('revoked_at')->where('publication_pending', false)
                                ->where(function (Builder $state): void {
                                    $state->where('state', 'pending')->orWhere(function (Builder $active): void {
                                        $active->where('state', 'active')->whereNotNull('control_public_key');
                                    });
                                }));
                    });
                    foreach ($allowed as $id => $route) {
                        $available->orWhere(function (Builder $exact) use ($id, $route, $manual): void {
                            $exact->where('targets.target_id', $id)->where('targets.reverse_listener_port', $route['port'])
                                ->where('targets.reverse_tunnel_identity', $route['tunnel_identity'])
                                ->whereNotExists(clone $manual);
                        });
                    }
                });
            })->orWhere(function (Builder $missing): void {
                $missing->whereNull('targets.reverse_listener_port')->whereExists(
                    DB::table('ssh_reverse_managed_enrollments')->selectRaw('1')
                        ->whereColumn('target_id', 'targets.target_id')
                        ->where(function (Builder $enrollment): void {
                            $enrollment->where('state', '!=', 'revoked')->orWhereColumn('target_record_id', '!=', 'targets.id');
                        })
                );
            });
        });
    }
}
