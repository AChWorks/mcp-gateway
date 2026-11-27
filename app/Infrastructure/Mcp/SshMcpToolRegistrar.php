<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshFileMcpToolHandlers;
use App\Application\Mcp\SshJobMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server\Builder;

/** Registers a focused, ordered portion of the existing MCP tool catalog. */
final readonly class SshMcpToolRegistrar
{
    public function __construct(
        private SshCommandMcpToolHandlers $sshCommands,
        private SshFileMcpToolHandlers $sshFiles,
        private SshJobMcpToolHandlers $sshJobs,
        private SshOperatorMcpToolRegistrar $operator,
        private OperationalSettings $settings,
        private VerifiedMcpCaller $principal,
    ) {}

    public function register(Builder $builder, Request $request): void
    {
        $commandLimits = $this->settings->sshCommandLimits();
        $jobLimits = $this->settings->sshJobLimits();
        $fileLimits = $this->settings->sshFileLimits();
        $jobOutputWindow = $this->settings->sshJobOutputWindowBytes();

        $builder
            ->addTool(
                handler: fn (string $target_id, string $command, int $timeout_seconds = 10): array => $this->sshCommands->run(
                    $this->principal->user($request), $target_id, $command, $timeout_seconds,
                ),
                name: 'ssh-command-run',
                description: 'Run one non-interactive command on an authorized host-key-pinned SSH Target. Root/sudo privileges belong to the remote OS account, not a Gateway sandbox. Input UTF-8 byte/time limits are Owner-configured and separate from file-transfer/Job limits. Never blindly retry an uncertain result.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        // JSON Schema maxLength is Unicode characters; runtime
                        // independently enforces the actual UTF-8 byte budget.
                        'command' => ['type' => 'string', 'minLength' => 1, 'maxLength' => $commandLimits['max_bytes']],
                        'timeout_seconds' => ['type' => 'integer', 'minimum' => 1, 'maximum' => $commandLimits['max_seconds'], 'default' => 10],
                    ],
                    'required' => ['target_id', 'command'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $request_id, string $script,
                    int $max_runtime_seconds = 60,
                ): array => $this->sshJobs->start(
                    $this->principal->user($request), $target_id, $this->principal->clientHash($request),
                    $request_id, $script, $max_runtime_seconds,
                ),
                name: 'ssh-job-start',
                description: 'Start a bounded background systemd SSH Job; requires command and file read/write grants. Script size is Owner-configurable in UTF-8 bytes. Identical UUID and arguments recover the retained Job without dispatch, even after route changes. On uncertain launch, poll job_id; never re-launch with a new UUID.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'request_id' => ['type' => 'string', 'format' => 'uuid'],
                        'script' => ['type' => 'string', 'minLength' => 1, 'maxLength' => $jobLimits['max_script_bytes']],
                        'max_runtime_seconds' => ['type' => 'integer', 'minimum' => 16, 'maximum' => $jobLimits['max_runtime_seconds'], 'default' => 60],
                    ],
                    'required' => ['target_id', 'request_id', 'script'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, ?string $status = null, ?string $cursor = null, int $limit = 20,
                ): array => $this->sshJobs->list(
                    $this->principal->user($request), $target_id, $this->principal->clientHash($request),
                    $status, $cursor, $limit,
                ),
                name: 'ssh-jobs-list',
                description: 'Discover retained SSH Jobs for this exact authenticated user, OAuth client/profile and authorized Target, including uncertain Jobs. Database-only, even if the authorized Target is paused or disconnected: no SSH connection, polling or relaunch. Use ssh-job-status for a selected job_id.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'status' => ['type' => 'string', 'enum' => [
                            'preparing', 'launch_unknown', 'running', 'cancel_requested',
                            'completed', 'failed', 'canceled', 'unsupported', 'retired',
                        ]],
                        'cursor' => ['type' => 'string', 'minLength' => 91, 'maxLength' => 91],
                        'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20],
                    ],
                    'required' => ['target_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $job_id): array => $this->sshJobs->status(
                    $this->principal->user($request), $target_id, $this->principal->clientHash($request), $job_id,
                ),
                name: 'ssh-job-status',
                description: 'Read retained Job metadata for the same user/client/Target. Fresh remote reconciliation requires current rights and original peer/artifact evidence. If remote state cannot be confirmed, preserve the recorded state and poll the same ID; never re-run the script.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'job_id' => ['type' => 'string', 'minLength' => 26, 'maxLength' => 26],
                    ],
                    'required' => ['target_id', 'job_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $job_id, string $stream = 'stdout',
                    int $offset = 0, int $length = 16384,
                ): array => $this->sshJobs->output(
                    $this->principal->user($request), $target_id, $this->principal->clientHash($request),
                    $job_id, $stream, $offset, $length,
                ),
                name: 'ssh-job-output',
                description: 'Read Owner-configured bounded windows of retained Job stdout/stderr per call as base64; use offset for more. Output unavailable is not EOF. On connection_busy, retry reads sequentially.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'job_id' => ['type' => 'string', 'minLength' => 26, 'maxLength' => 26],
                        'stream' => ['type' => 'string', 'enum' => ['stdout', 'stderr'], 'default' => 'stdout'],
                        'offset' => ['type' => 'integer', 'minimum' => 0, 'maximum' => 1048576, 'default' => 0],
                        'length' => ['type' => 'integer', 'minimum' => 1, 'maximum' => $jobOutputWindow, 'default' => min(16384, $jobOutputWindow)],
                    ],
                    'required' => ['target_id', 'job_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $job_id): array => $this->sshJobs->cancel(
                    $this->principal->user($request), $target_id, $this->principal->clientHash($request), $job_id,
                ),
                name: 'ssh-job-cancel',
                description: 'Stop an exact systemd Job. canceled means either the script was never admitted or the exact unit was stopped and verified inactive with MainPID/ControlPID zero; cancel_requested remains unconfirmed until reconciled.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'job_id' => ['type' => 'string', 'minLength' => 26, 'maxLength' => 26],
                    ],
                    'required' => ['target_id', 'job_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $path): array => $this->sshFiles->stat(
                    $this->principal->user($request), $target_id, $path,
                ),
                name: 'ssh-file-stat',
                description: 'Inspect metadata for one absolute remote SFTP path on an explicitly authorized SSH Target.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'path' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 1024],
                    ],
                    'required' => ['target_id', 'path'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $path, int $limit = 100, ?string $cursor = null): array => $this->sshFiles->list(
                    $this->principal->user($request), $target_id, $path, $limit, $cursor,
                ),
                name: 'ssh-file-list',
                description: 'Page a remote SFTP directory with bounded entries and a signed continuation cursor. Pass next_cursor with the same path/limit/Target. Stable directory contents are required: SFTP does not provide a transactional snapshot; concurrent mutations may shift entries. Pagination rescans skipped entries without retaining them in memory.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'path' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 1024],
                        'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 100],
                        'cursor' => ['type' => 'string', 'minLength' => 66, 'maxLength' => 80],
                    ],
                    'required' => ['target_id', 'path'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $path, int $offset = 0, int $length = 16384,
                    ?int $expected_size = null, ?int $expected_mtime = null,
                ): array => $this->sshFiles->read(
                    $this->principal->user($request), $target_id, $path, $offset, $length, $expected_size, $expected_mtime,
                ),
                name: 'ssh-file-read',
                description: 'Read a bounded Owner-configured SFTP file window as base64; offset allows larger reads over multiple calls. Size+mtime checks are best-effort.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'path' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 1024],
                        'offset' => ['type' => 'integer', 'minimum' => 0, 'maximum' => 1099511627776, 'default' => 0],
                        'length' => ['type' => 'integer', 'minimum' => 1, 'maximum' => $fileLimits['read_bytes'], 'default' => min(16384, $fileLimits['read_bytes'])],
                        'expected_size' => ['type' => 'integer', 'minimum' => 0],
                        'expected_mtime' => ['type' => 'integer', 'minimum' => 0],
                    ],
                    'required' => ['target_id', 'path'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (
                    string $target_id, string $path, string $content_base64, bool $overwrite = false,
                    ?int $expected_size = null, ?int $expected_mtime = null,
                ): array => $this->sshFiles->write(
                    $this->principal->user($request), $target_id, $path, $content_base64, $overwrite,
                    $expected_size, $expected_mtime,
                ),
                name: 'ssh-file-write',
                description: 'Create or atomically replace one SFTP file (Owner-configured decoded-byte window); NOT an append/chunk upload. overwrite=true replaces, size+mtime checks are not CAS. On outcome_unknown, inspect before retrying. Whole-file transfer uses a separate HTTPS endpoint.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'path' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 1024],
                        'content_base64' => ['type' => 'string', 'maxLength' => 4 * intdiv($fileLimits['write_bytes'] + 2, 3)],
                        'overwrite' => ['type' => 'boolean', 'default' => false],
                        'expected_size' => ['type' => 'integer', 'minimum' => 0],
                        'expected_mtime' => ['type' => 'integer', 'minimum' => 0],
                    ],
                    'required' => ['target_id', 'path', 'content_base64'],
                    'additionalProperties' => false,
                ],
            );

        $this->operator->register($builder, $request);
    }
}
