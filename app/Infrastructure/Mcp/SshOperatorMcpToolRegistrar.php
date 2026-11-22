<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\SshOperatorMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshOperatorProbes;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server\Builder;

/** Focused public contracts over the established SSH Command/SFTP runtimes. */
final readonly class SshOperatorMcpToolRegistrar
{
    public function __construct(
        private SshOperatorMcpToolHandlers $tools,
        private OperationalSettings $settings,
        private VerifiedMcpCaller $principal,
    ) {}

    public function register(Builder $builder, Request $request): void
    {
        $seconds = $this->settings->sshCommandLimits()['max_seconds'];
        $file = $this->settings->sshFileLimits();
        $maxJournalLines = max(1, intdiv($this->settings->sshCommandOutputLimits()['stdout_bytes'], 64));
        $commandRead = new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true);
        $commandWrite = new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true);
        $target = ['type' => 'string', 'minLength' => 1, 'maxLength' => 64];
        $path = ['type' => 'string', 'minLength' => 1, 'maxLength' => 1024];
        $timeout = ['type' => 'integer', 'minimum' => 1, 'maximum' => $seconds, 'default' => min(10, $seconds)];

        $builder
            ->addTool(
                handler: fn (
                    string $target_id, array $sections = [], ?string $service = null, int $timeout_seconds = 10,
                ): array => $this->tools->system(
                    $this->principal->user($request), $target_id, $sections, $service, $timeout_seconds,
                ),
                name: 'ssh-system-inspect',
                description: 'Inspect requested system/uptime/load/CPU/memory/storage/process/service/listener observations with source, units and partial/failure status. Uses the existing ssh.command.run grant and OS account; readOnlyHint is descriptive, not a command sandbox. No permanent agent.',
                annotations: $commandRead,
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => $target,
                        'sections' => ['type' => 'array', 'items' => [
                            'type' => 'string', 'enum' => SshOperatorProbes::systemSections(),
                        ], 'uniqueItems' => true, 'default' => ['system', 'uptime', 'load', 'cpu', 'memory', 'storage']],
                        'service' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200],
                        'timeout_seconds' => $timeout,
                    ],
                    'required' => ['target_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $probe, string $host, ?int $port = null,
                    string $scheme = 'https', string $path = '/', ?string $dns_name = null,
                    int $timeout_seconds = 10,
                ): array => $this->tools->network(
                    $this->principal->user($request), $target_id, $probe, $host, $port,
                    $scheme, $path, $dns_name, $timeout_seconds,
                ),
                name: 'ssh-network-diagnose',
                description: 'Probe exactly one destination from an authorized SSH Target: DNS, route, TCP connect, verified TLS, HTTP, ICMP latency or protocol-aware UDP DNS response. Distinguish status/errors/unsupported; sending a UDP packet alone is never proof. Uses ssh.command.run grant, not an OS sandbox.',
                annotations: $commandRead,
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => $target,
                        'probe' => ['type' => 'string', 'enum' => ['dns', 'route', 'tcp', 'tls', 'http', 'latency', 'udp_dns']],
                        'host' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 253],
                        'port' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 65535],
                        'scheme' => ['type' => 'string', 'enum' => ['http', 'https'], 'default' => 'https'],
                        'path' => $path,
                        'dns_name' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 253],
                        'timeout_seconds' => $timeout,
                    ],
                    'required' => ['target_id', 'probe', 'host'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $source = 'journal', ?string $service = null, ?string $path = null,
                    ?string $since = null, ?string $until = null, ?string $level = null,
                    ?string $cursor = null, int $lines = 50, int $offset = 0, ?int $length = null,
                    ?int $expected_size = null, ?int $expected_mtime = null, int $timeout_seconds = 10,
                ): array => $this->tools->logs(
                    $this->principal->user($request), $target_id, $source, $service, $path,
                    $since, $until, $level, $cursor, $lines, $offset, $length,
                    $expected_size, $expected_mtime, $timeout_seconds,
                ),
                name: 'ssh-logs-query',
                description: 'Query bounded journald JSON entries with UTC timestamps, service/time/level filters and native cursor, or bounded SFTP file byte windows with offset, size/mtime and base64. Journal requires ssh.command.run, file mode ssh.file.read. No log warehouse, continuous tail or assumed per-line file timestamps.',
                annotations: $commandRead,
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => $target,
                        'source' => ['type' => 'string', 'enum' => ['journal', 'file'], 'default' => 'journal'],
                        'service' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200],
                        'path' => $path,
                        'since' => ['type' => 'string', 'format' => 'date-time'],
                        'until' => ['type' => 'string', 'format' => 'date-time'],
                        'level' => ['type' => 'string', 'enum' => ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']],
                        'cursor' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 2048],
                        'lines' => ['type' => 'integer', 'minimum' => 1, 'maximum' => $maxJournalLines, 'default' => min(50, $maxJournalLines)],
                        'offset' => ['type' => 'integer', 'minimum' => 0, 'maximum' => 1099511627776, 'default' => 0],
                        'length' => ['type' => 'integer', 'minimum' => 1, 'maximum' => $file['read_bytes']],
                        'expected_size' => ['type' => 'integer', 'minimum' => 0],
                        'expected_mtime' => ['type' => 'integer', 'minimum' => 0],
                        'timeout_seconds' => $timeout,
                    ],
                    'required' => ['target_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $path, string $find, string $replace,
                    bool $apply = false, ?string $expected_sha256 = null,
                ): array => $this->tools->patch(
                    $this->principal->user($request), $target_id, $path,
                    $find, $replace, $apply, $expected_sha256,
                ),
                name: 'ssh-file-patch',
                description: 'Preview one unique UTF-8 localized replacement; apply=true requires the exact preview baseline SHA256 plus ssh.file.read AND ssh.file.write grants. Preserves/independently verifies mode and owner/group via existing SFTP staging. Source hash/size/mtime checks are best effort, NOT remote atomic CAS; inspect unknown outcomes, never blindly replay. No automatic service reload or rollback.',
                annotations: $commandWrite,
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => $target,
                        'path' => $path,
                        'find' => ['type' => 'string', 'minLength' => 1, 'maxLength' => $file['write_bytes']],
                        'replace' => ['type' => 'string', 'maxLength' => $file['write_bytes']],
                        'apply' => ['type' => 'boolean', 'default' => false],
                        'expected_sha256' => ['type' => 'string', 'pattern' => '^[a-f0-9]{64}$'],
                    ],
                    'required' => ['target_id', 'path', 'find', 'replace'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $check, string $expected,
                    ?string $path = null, ?string $service = null, ?string $host = null,
                    ?int $port = null, string $scheme = 'https', int $timeout_seconds = 10,
                    ?string $before = null,
                ): array => $this->tools->verify(
                    $this->principal->user($request), $target_id, $check, $expected,
                    $path, $service, $host, $port, $scheme, $timeout_seconds, $before,
                ),
                name: 'ssh-change-verify',
                description: 'Independent one-check post-change observation: file SHA256, systemd service state, TCP open or HTTP status. Compare expected against observed and optional before evidence. Reload/syntax command exit zero alone never proves service health; unknown/unsupported remain explicit. Uses existing ssh.command.run permission and OS identity.',
                annotations: $commandRead,
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => $target,
                        'check' => ['type' => 'string', 'enum' => ['file_sha256', 'service_state', 'tcp_open', 'http_status']],
                        'expected' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200],
                        'path' => $path,
                        'service' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200],
                        'host' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 253],
                        'port' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 65535],
                        'scheme' => ['type' => 'string', 'enum' => ['http', 'https'], 'default' => 'https'],
                        'timeout_seconds' => $timeout,
                        'before' => ['type' => 'string', 'maxLength' => 200],
                    ],
                    'required' => ['target_id', 'check', 'expected'],
                    'additionalProperties' => false,
                ],
            );
    }
}
