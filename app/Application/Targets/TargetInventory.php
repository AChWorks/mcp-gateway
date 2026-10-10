<?php

namespace App\Application\Targets;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use InvalidArgumentException;

final class TargetInventory
{
    public function __construct(private readonly AccessControl $access) {}

    public const ADMIN_PAGE_SIZE = 50;

    public const MCP_DEFAULT_LIMIT = 100;

    public const MCP_MAX_LIMIT = 100;

    // Bounded left join instead of one extra eager-load query per inventory
    // page. Never select pinned host keys or credential payloads in lists.
    private const SSH_COLUMNS = [
        'sshc.host as ssh_cfg_host',
        'sshc.port as ssh_cfg_port',
        'sshc.username as ssh_cfg_username',
        'sshc.observed_peer_ip as ssh_cfg_peer',
        'sshc.observed_at as ssh_cfg_observed',
    ];

    /**
     * @return array{items:list<Target>,page:int,per_page:int,has_more:bool}
     */
    public function adminPage(
        User $user,
        int $page = 1,
        ?string $search = null,
        ?string $connectionState = null,
        ?string $connectorType = null,
    ): array {
        $page = max(1, $page);
        $search = $this->search($search);
        $connectionState = $this->connectionState($connectionState);
        $connectorType = $this->connectorType($connectorType);

        $query = $this->access->scopeTargets(
            Target::query()->select([
                'id',
                'target_id',
                'display_name',
            ]),
            $user,
            GatewayPermission::TargetsView,
        );

        $this->applyFilters($query, $search, $connectionState, $connectorType);

        $rows = $query
            ->orderBy('display_name')
            ->orderBy('target_id')
            ->offset(($page - 1) * self::ADMIN_PAGE_SIZE)
            ->limit(self::ADMIN_PAGE_SIZE + 1)
            ->get();
        $hasMore = $rows->count() > self::ADMIN_PAGE_SIZE;
        $pageRows = $rows->take(self::ADMIN_PAGE_SIZE)->values();

        if ($pageRows->isEmpty()) {
            $items = [];
        } else {
            $detailQuery = Target::query()
                ->leftJoin('ssh_direct_target_configs as sshc', 'sshc.target_record_id', '=', 'targets.id')
                ->select([
                    'targets.id',
                    'targets.target_id',
                    'targets.display_name',
                    'targets.connector_type',
                    'targets.connection_state',
                    'targets.last_error_code',
                    'targets.last_tested_at',
                    'targets.connected_at',
                    'targets.last_success_at',
                    'targets.last_failure_at',
                    'targets.last_failure_code',
                    ...self::SSH_COLUMNS,
                ]);
            $targetsById = $this->access
                ->scopeTargets($detailQuery, $user, GatewayPermission::TargetsView)
                ->whereIn('targets.id', $pageRows->pluck('id')->all())
                ->get()
                ->keyBy('id');

            $items = $pageRows
                ->map(static fn (Target $row): ?Target => $targetsById->get($row->id))
                ->filter(static fn (?Target $target): bool => $target instanceof Target)
                ->values()
                ->all();
            $this->bindProjectedSshConfig($items);
        }

        return [
            'items' => $items,
            'page' => $page,
            'per_page' => self::ADMIN_PAGE_SIZE,
            'has_more' => $hasMore,
        ];
    }

    /**
     * @return array{items:list<Target>,limit:int,has_more:bool,next_cursor:?string}
     */
    public function mcpPage(
        User $user,
        ?string $cursor = null,
        int $limit = self::MCP_DEFAULT_LIMIT,
        ?string $search = null,
        ?string $connectionState = null,
        ?string $connectorType = null,
    ): array {
        if ($limit < 1 || $limit > self::MCP_MAX_LIMIT) {
            throw new InvalidArgumentException(sprintf(
                'limit must be between 1 and %d.',
                self::MCP_MAX_LIMIT,
            ));
        }

        $cursor = $this->cursor($cursor);
        $search = $this->search($search);
        $connectionState = $this->connectionState($connectionState);
        $connectorType = $this->connectorType($connectorType);

        $query = $this->access->scopeTargets(
            Target::query()
                ->leftJoin('ssh_direct_target_configs as sshc', 'sshc.target_record_id', '=', 'targets.id')
                ->select([
                    'targets.id',
                    'targets.target_id',
                    'targets.display_name',
                    'targets.connector_type',
                    'targets.connection_state',
                    ...self::SSH_COLUMNS,
                ]),
            $user,
            GatewayPermission::TargetsView,
        );

        $this->applyFilters($query, $search, $connectionState, $connectorType);

        if ($cursor !== null) {
            $query->where('target_id', '>', $cursor);
        }

        $rows = $query
            ->orderBy('target_id')
            ->limit($limit + 1)
            ->get();
        $items = $rows->take($limit)->values();
        $this->bindProjectedSshConfig($items->all());
        $hasMore = $rows->count() > $limit;
        $last = $items->last();

        return [
            'items' => $items->all(),
            'limit' => $limit,
            'has_more' => $hasMore,
            'next_cursor' => $hasMore && $last instanceof Target ? $last->target_id : null,
        ];
    }

    /** @param Builder<Target> $query */
    private function applyFilters(Builder $query, ?string $search, ?string $connectionState, ?string $connectorType): void
    {
        if ($search !== null) {
            [$lookupHost, $lookupPort, $lookupUsername] = $this->sshLookup($search);
            $query->where(function (Builder $query) use ($search, $lookupHost, $lookupPort, $lookupUsername): void {
                $query
                    ->where('display_name', 'like', '%'.$search.'%')
                    ->orWhere('target_id', 'like', '%'.$search.'%')
                    // An authorized local lookup, no DNS/network/credential access.
                    // Same-IP accounts remain distinct and require explicit target_id.
                    ->orWhereHas('sshConfig', static function (Builder $ssh) use ($lookupHost, $lookupPort, $lookupUsername): void {
                        $ssh->where(static function (Builder $addresses) use ($lookupHost): void {
                            $addresses->where('host', $lookupHost)->orWhere('observed_peer_ip', $lookupHost);
                        });
                        if ($lookupPort !== null) {
                            $ssh->where('port', $lookupPort);
                        }
                        if ($lookupUsername !== null) {
                            $ssh->where('username', $lookupUsername);
                        }
                    });
            });
        }

        if ($connectionState !== null) {
            $query->where('connection_state', $connectionState);
        }
        if ($connectorType !== null) {
            $query->where('connector_type', $connectorType);
        }
    }

    /**
     * Normalize local SSH host/IP/optional port and account search only.
     * A search term never selects the remote target for an action.
     *
     * @return array{string,?int,?string}
     */
    private function sshLookup(string $search): array
    {
        $host = strtolower($search);
        $username = null;
        if (str_contains($host, '@')) {
            [$username, $host] = explode('@', $host, 2);
        }

        $port = null;
        if (preg_match('/^\[([^\]]+)\]:(\d{1,5})$/D', $host, $matches) === 1
            || preg_match('/^([^:]+):(\d{1,5})$/D', $host, $matches) === 1) {
            $host = $matches[1];
            $port = (int) $matches[2];
            if ($port < 1 || $port > 65535) {
                return ['', null, null];
            }
        } elseif (preg_match('/^\[([^\]]+)\]$/D', $host, $matches) === 1) {
            $host = $matches[1];
        }

        $ip = @inet_pton($host);
        if ($ip !== false) {
            $host = (string) inet_ntop($ip);
        }

        return [$host, $port, $username];
    }

    /**
     * Hydrate a read-only SSH presentation relation from a unique indexed
     * left join. Inventory never fetches sensitive pin/credential material.
     *
     * @param  list<Target>  $targets
     */
    private function bindProjectedSshConfig(array $targets): void
    {
        foreach ($targets as $target) {
            $host = $target->getAttribute('ssh_cfg_host');
            $config = null;
            if (is_string($host) && $host !== '') {
                $config = new SshTargetConfig;
                $config->forceFill([
                    'host' => $host,
                    'port' => $target->getAttribute('ssh_cfg_port'),
                    'username' => $target->getAttribute('ssh_cfg_username'),
                    'observed_peer_ip' => $target->getAttribute('ssh_cfg_peer'),
                    'observed_at' => $target->getAttribute('ssh_cfg_observed'),
                ]);
            }
            $target->setRelation('sshConfig', $config);
            foreach (['ssh_cfg_host', 'ssh_cfg_port', 'ssh_cfg_username', 'ssh_cfg_peer', 'ssh_cfg_observed'] as $column) {
                $target->offsetUnset($column);
            }
        }
    }

    private function cursor(?string $value): ?string
    {
        $value = $this->nullableTrim($value);

        if ($value !== null && mb_strlen($value) > 64) {
            throw new InvalidArgumentException('cursor exceeds the supported target ID length.');
        }

        return $value;
    }

    private function search(?string $value): ?string
    {
        $value = $this->nullableTrim($value);

        if ($value !== null && mb_strlen($value) > 160) {
            throw new InvalidArgumentException('search exceeds the supported length.');
        }

        return $value;
    }

    private function connectionState(?string $value): ?string
    {
        $value = $this->nullableTrim($value);

        if ($value !== null && TargetConnectionState::tryFrom($value) === null) {
            throw new InvalidArgumentException('connection_state is not supported.');
        }

        return $value;
    }

    private function connectorType(?string $value): ?string
    {
        $value = $this->nullableTrim($value);
        if ($value !== null && ! in_array($value, [
            'wp_ai_bridge', 'ai_server_agent', 'ssh_direct',
        ], true)) {
            throw new InvalidArgumentException('connector_type is not supported.');
        }

        return $value;
    }

    private function nullableTrim(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
