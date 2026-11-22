<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\ChatGptFileToolAvailability;
use App\Application\Mcp\TargetFileInputMcpToolHandlers;
use App\Application\Mcp\WordpressFileInputMcpToolHandlers;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server\Builder;

/** Registers a focused, ordered portion of the existing MCP tool catalog. */
final readonly class FileTransferMcpToolRegistrar
{
    public function __construct(
        private WordpressFileInputMcpToolHandlers $wordpressFiles,
        private TargetFileInputMcpToolHandlers $targetFiles,
        private ChatGptFileToolAvailability $fileAvailability,
        private VerifiedMcpCaller $principal,
    ) {}

    public function register(Builder $builder, Request $request): void
    {
        $authenticatedProfile = $request->attributes->get('oauth_client_profile_key');
        $fileModes = $this->fileAvailability->modes($this->principal->user($request),
            is_string($authenticatedProfile) ? $authenticatedProfile : null);
        // Exact OpenAI FileParams object schema, shared across both MCP tools.
        $fileParamSchema = [
            'type' => 'object',
            'properties' => [
                'download_url' => ['type' => 'string'],
                'file_id' => ['type' => 'string'],
                'mime_type' => ['type' => 'string'],
                'file_name' => ['type' => 'string'],
            ],
            'required' => ['download_url', 'file_id'],
            'additionalProperties' => false,
        ];

        if ($fileModes['wordpress']) {
            $builder->addTool(
                handler: fn (string $target_id, array $file): array => $this->wordpressFiles->receive(
                    $this->principal->user($request), $target_id, $file,
                ),
                name: 'wordpress-file-input',
                description: 'Use only with a genuine ChatGPT host-supplied FileParams file for an authorized WordPress Target; an attachment in the chat is NOT automatically a valid file argument. Stage and SHA-256 verify a private transfer_id without creating Media or publishing content. For an authorized import, separately call wordpress-ability-execute with wp-ai-bridge/transfer-media-import and that transfer_id. Use target-file-input with mode=wordpress_media_stage for the same staging operation. Never invent download_url or file_id.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'file' => $fileParamSchema,
                    ],
                    'required' => ['target_id', 'file'],
                    'additionalProperties' => false,
                ],
                meta: ['openai/fileParams' => ['file']],
            );
        }
        if ($fileModes['wordpress'] || $fileModes['ssh']) {
            $builder->addTool(
                handler: fn (string $target_id, array $file, string $mode, ?array $ssh_destination = null): array => $this->targetFiles->receive(
                    $this->principal->user($request), $target_id, $file, $mode, $ssh_destination,
                ),
                name: 'target-file-input',
                description: 'Use only with genuine ChatGPT host-supplied FileParams, not an invented download_url/file_id or an ordinary chat attachment. Select an authorized Target and exact mode: wordpress_media_stage stages a private verified transfer_id (no Media import or publish); ssh_sftp_upload writes an SFTP file to ssh_destination.path using a pre-provisioned private_staging_dir, with explicit overwrite opt-in. This can change remote files. Verify an uncertain SSH upload before any retry; arbitrary URLs and executable packages are rejected.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'file' => $fileParamSchema,
                        'mode' => ['type' => 'string', 'enum' => [
                            ...($fileModes['wordpress'] ? ['wordpress_media_stage'] : []),
                            ...($fileModes['ssh'] ? ['ssh_sftp_upload'] : []),
                        ]],
                        'ssh_destination' => [
                            'type' => 'object',
                            'properties' => [
                                'path' => ['type' => 'string', 'minLength' => 2, 'maxLength' => 1024],
                                'private_staging_dir' => ['type' => 'string', 'minLength' => 2, 'maxLength' => 1024],
                                'overwrite' => ['type' => 'boolean', 'default' => false],
                                'expected_size' => ['type' => 'integer', 'minimum' => 0],
                                'expected_mtime' => ['type' => 'integer', 'minimum' => 0],
                            ],
                            'required' => ['path', 'private_staging_dir'],
                            'additionalProperties' => false,
                        ],
                    ],
                    'required' => ['target_id', 'file', 'mode'],
                    'additionalProperties' => false,
                ],
                meta: ['openai/fileParams' => ['file']],
            );
        }
    }
}
