<?php

namespace App\Application\Admin;

use App\Application\Targets\TargetCheckEvidence;
use App\Application\Targets\TargetRouteAvailability;
use App\Domain\Targets\Target;
use Illuminate\Support\Facades\DB;

/** Scoped page-only projection of persisted observations and selected-route policy. */
final readonly class TargetHealthAdmin
{
    public function __construct(private TargetRouteAvailability $routes) {}

    /**
     * @param  list<Target>  $targets
     * @return array<string,array{route_unavailable:bool,checks:list<array{kind:string,label:string,time:?string,error:?string,history:?string,tone:string}>,attention:bool}>
     */
    public function forTargets(array $targets): array
    {
        if ($targets === []) {
            return [];
        }
        $ids = array_map(static fn (Target $target): string => (string) $target->getKey(), $targets);
        $rows = DB::table('target_check_evidence')->whereIn('target_record_id', $ids)->get()->groupBy('target_record_id');
        $unavailable = array_fill_keys($this->routes->unavailable()->whereIn('targets.id', $ids)->pluck('targets.id')->all(), true);
        $arvanIds = array_map(static fn (Target $target): string => (string) $target->getKey(),
            array_filter($targets, static fn (Target $target): bool => $target->connector_type === 'arvancloud'));
        $probePaths = $arvanIds === [] ? [] : DB::table('arvan_api_target_configs')->whereIn('target_record_id', $arvanIds)->pluck('probe_path', 'target_record_id')->all();
        $result = [];
        foreach ($targets as $target) {
            $id = (string) $target->getKey();
            $slots = $rows->get($id)?->keyBy('kind');
            $kinds = match ($target->connector_type) {
                'ssh_direct' => [TargetCheckEvidence::SSH_LOGIN => __('SSH host and login')],
                'wp_ai_bridge' => [TargetCheckEvidence::WORDPRESS_METADATA => __('WordPress public metadata (not OAuth)')],
                'arvancloud' => [TargetCheckEvidence::ARVAN_HTTPS => __('HTTPS HEAD (no key)'), TargetCheckEvidence::ARVAN_AUTH => __('Authenticated GET')],
                default => [],
            };
            $checks = [];
            $failure = false;
            $routeUnavailable = isset($unavailable[$id]);
            foreach ($kinds as $kind => $name) {
                $row = $slots?->get($kind);
                $optional = $kind === TargetCheckEvidence::ARVAN_AUTH && ($probePaths[$id] ?? null) === null;
                $current = ! $routeUnavailable && ! $optional && $row !== null && $row->observed_at !== null && $row->transport_revision !== null
                    && (int) $row->transport_revision === (int) $target->transport_revision;
                $failed = $current && $row->error_code !== null;
                $history = $row !== null && $row->last_failure_at !== null
                    ? __('Historical failure: :code at :time', ['code' => $row->last_failure_code, 'time' => $row->last_failure_at]) : null;
                if ($row !== null && $row->observed_at !== null && ! $current) {
                    $history = __('Historical check: :result at :time', [
                        'result' => $row->error_code ?? __('Succeeded'), 'time' => $row->observed_at,
                    ]);
                }
                $checks[] = [
                    'kind' => $name,
                    'label' => $optional ? __('Authentication probe not configured (optional)')
                        : ($current ? ($failed ? __('Last check failed') : __('Last check succeeded')) : __('Current route not verified')),
                    'time' => $current ? (string) $row->observed_at : null,
                    'error' => $failed ? (string) $row->error_code : null,
                    'history' => $failed ? null : $history,
                    'tone' => $failed ? 'warning' : 'neutral',
                ];
                $failure = $failure || $failed;
            }
            $result[$target->target_id] = ['route_unavailable' => $routeUnavailable, 'checks' => $checks,
                'attention' => $failure || $routeUnavailable];
        }

        return $result;
    }
}
