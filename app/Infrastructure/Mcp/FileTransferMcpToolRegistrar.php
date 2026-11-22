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
                description: 'ONLY stage and hash-verify a host-provided ChatGPT file into an authorized WordPress private Media transfer. This tool cannot publish native Media: separately invoke wordpress-ability-execute with wp-ai-bridge/transfer-media-import and the returned stable transfer_id after explicit authorization. Repeating this file-input can never create a second Media item. Builder Write/upload_files are checked before signed-file download. A finite Owner-configurable WordPress-mode file budget (separate from Bridge limits). No arbitrary URLs or executable packages.',
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
                description: 'Transfer a ChatGPT file to an explicitly authorized selected WordPress or SSH Target. WordPress stages a verified private Media lease (no publication). SSH writes verified SFTP bytes to an explicit destination and pre-provisioned private staging directory; overwrite requires opt-in. All signed-file URLs, current Target grants, SHA-256, finite budgets and uncertain-effect recovery are enforced. No arbitrary URLs or executable packages.',
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
