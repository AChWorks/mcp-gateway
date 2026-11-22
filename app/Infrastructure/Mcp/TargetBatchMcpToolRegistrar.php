<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\TargetBatchMcpToolHandlers;
use App\Application\Operations\OperationalSettings;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server\Builder;

/** Explicit, first-party Batch operations; no arbitrary Tool invocation. */
final readonly class TargetBatchMcpToolRegistrar
{
    public function __construct(
        private TargetBatchMcpToolHandlers $handlers,
        private VerifiedMcpCaller $caller,
        private OperationalSettings $settings,
    ) {}

    public function register(Builder $builder, Request $request): void
    {
        $sshLimits = $this->settings->sshCommandLimits();
        $parallelism = $this->settings->batchLimits()['max_parallelism'];
        $targets = ['type' => 'array', 'minItems' => 1,
            'items' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64]];
        $common = [
            'target_ids' => $targets,
            'execution_mode' => ['type' => 'string', 'enum' => ['concurrent', 'rolling'], 'default' => 'concurrent'],
            'stop_on_failure' => ['type' => 'boolean', 'default' => false],
            'parallelism' => ['type' => 'integer', 'minimum' => 1, 'maximum' => $parallelism, 'default' => 1],
        ];
        $ssh = [
            ...$common,
            'command' => ['type' => 'string', 'minLength' => 1, 'maxLength' => $sshLimits['max_bytes']],
            'timeout_seconds' => ['type' => 'integer', 'minimum' => 1,
                'maximum' => $sshLimits['max_seconds'], 'default' => 10],
        ];
        $previewToken = ['type' => 'string', 'pattern' => '^[0-9]{10}\\.[a-f0-9]{64}$'];
        $batchId = ['type' => 'string', 'minLength' => 26, 'maxLength' => 26];
        $requestId = ['type' => 'string', 'format' => 'uuid'];
        $builder->addTool(
            handler: fn (array $target_ids, string $command, int $timeout_seconds = 10,
                string $execution_mode = 'concurrent', bool $stop_on_failure = false, int $parallelism = 1): array => $this->handlers->previewSsh(
                    $request, $this->caller->user($request), $target_ids, $command,
                    $timeout_seconds, $execution_mode, $stop_on_failure, $parallelism,
                ),
            name: 'ssh-batch-preview',
            description: 'Preview a precise SSH command Batch selection without remote effects. Returns bound per-Target eligibility, resource/mode plan and a short-lived exact-plan preview_token. A preview is not permission to bypass current Target grants.',
            annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
            inputSchema: ['type' => 'object', 'properties' => $ssh,
                'required' => ['target_ids', 'command'], 'additionalProperties' => false],
        )->addTool(
            handler: fn (string $request_id, array $target_ids, string $command, string $preview_token,
                int $timeout_seconds = 10, string $execution_mode = 'concurrent',
                bool $stop_on_failure = false, int $parallelism = 1): array => $this->handlers->runSsh(
                    $request, $this->caller->user($request), $request_id, $target_ids,
                    $command, $preview_token, $timeout_seconds, $execution_mode,
                    $stop_on_failure, $parallelism,
                ),
            name: 'ssh-batch-run',
            description: 'Persist an authorized explicit SSH Target selection after exact-plan preview. Detached worker executes each queued child through the existing pinned SSH runtime. A stable request_id deduplicates; outcome_unknown is not replayed. This call only queues, not proves completion.',
            annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
            inputSchema: ['type' => 'object', 'properties' => [...$ssh,
                'request_id' => $requestId, 'preview_token' => $previewToken],
                'required' => ['request_id', 'target_ids', 'command', 'preview_token'],
                'additionalProperties' => false],
        )->addTool(
            handler: fn (array $target_ids, string $execution_mode = 'concurrent',
                bool $stop_on_failure = false, int $parallelism = 1): array => $this->handlers->previewWordpress(
                    $request, $this->caller->user($request), $target_ids,
                    $execution_mode, $stop_on_failure, $parallelism,
                ),
            name: 'wordpress-bridge-batch-preview',
            description: 'Preview a fixed, authorized read-only WordPress Bridge information operation over explicit Targets; no arbitrary Ability or content publication.',
            annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
            inputSchema: ['type' => 'object', 'properties' => $common,
                'required' => ['target_ids'], 'additionalProperties' => false],
        )->addTool(
            handler: fn (string $request_id, array $target_ids, string $preview_token,
                string $execution_mode = 'concurrent', bool $stop_on_failure = false, int $parallelism = 1): array => $this->handlers->runWordpress(
                    $request, $this->caller->user($request), $request_id, $target_ids,
                    $preview_token, $execution_mode, $stop_on_failure, $parallelism,
                ),
            name: 'wordpress-bridge-batch-read',
            description: 'Queue only fixed read-only wp-ai-bridge/bridge-info calls across explicit authorized WordPress Targets. Never publishes, updates or deletes content. View actual result via target-batch-status.',
            annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
            inputSchema: ['type' => 'object', 'properties' => [...$common,
                'request_id' => $requestId, 'preview_token' => $previewToken],
                'required' => ['request_id', 'target_ids', 'preview_token'],
                'additionalProperties' => false],
        )->addTool(
            handler: fn (string $batch_id, int $offset = 0, int $limit = 50): array => $this->handlers->status($request, $this->caller->user($request), $batch_id, $offset, $limit),
            name: 'target-batch-status',
            description: 'Read retained per-Target Batch evidence using the initiating verified OAuth client identity, even after the original HTTP request ended. Unknown, failed and cancel_requested never imply successful remote effects.',
            annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
            inputSchema: ['type' => 'object', 'properties' => [
                'batch_id' => $batchId,
                'offset' => ['type' => 'integer', 'minimum' => 0, 'default' => 0],
                'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 50]],
                'required' => ['batch_id'], 'additionalProperties' => false],
        )->addTool(
            handler: fn (?string $cursor = null, int $limit = 20): array => $this->handlers->list($request, $this->caller->user($request), $cursor, $limit),
            name: 'target-batches-list',
            description: 'List retained Batch identities for this exact authenticated User and Client without a remote operation.',
            annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: false),
            inputSchema: ['type' => 'object', 'properties' => [
                'cursor' => $batchId,
                'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 20]],
                'required' => [], 'additionalProperties' => false],
        )->addTool(
            handler: fn (string $batch_id): array => $this->handlers->cancel($request, $this->caller->user($request), $batch_id),
            name: 'target-batch-cancel',
            description: 'Cancel not-yet-dispatched children. For in-flight remote effects, records cancel_requested only; it does NOT guarantee SSH process termination or permit replay of an uncertain result.',
            annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: false),
            inputSchema: ['type' => 'object', 'properties' => ['batch_id' => $batchId],
                'required' => ['batch_id'], 'additionalProperties' => false],
        );
    }
}
