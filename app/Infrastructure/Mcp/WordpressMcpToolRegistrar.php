<?php

namespace App\Infrastructure\Mcp;

use App\Application\Mcp\WordpressTargetMcpToolHandlers;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server\Builder;

/** Registers a focused, ordered portion of the existing MCP tool catalog. */
final readonly class WordpressMcpToolRegistrar
{
    public function __construct(
        private WordpressTargetMcpToolHandlers $wordpress,
        private VerifiedMcpCaller $principal,
    ) {}

    public function register(Builder $builder, Request $request): void
    {
        $builder
            ->addTool(
                handler: fn (
                    string $target_id,
                    ?string $ability = null,
                    int $page = 1,
                    int $per_page = 10,
                    ?string $namespace = null,
                    ?string $search = null,
                ): array => $this->wordpress->read(
                    $this->principal->user($request), $target_id, $ability, $page, $per_page, $namespace, $search,
                ),
                name: 'wordpress-abilities-read',
                description: 'Read WordPress Ability metadata for an explicitly authorized Target.',
                annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'ability' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        'page' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1],
                        'per_page' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 10],
                        'namespace' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        'search' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                    ],
                    'required' => ['target_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $title, string $content, string $operation_id): array => $this->wordpress->publishCreate(
                    $this->principal->user($request), $target_id, $title, $content, $operation_id,
                    ...$this->principal->clientIdentity($request),
                ),
                name: 'wordpress-content-publish-create',
                description: 'Create exactly one published WordPress post on an authorized Target. Requires an Owner-managed semantic User + Target Group grant for ordinary accounts, plus independently enabled AI access and OAuth client authorization and an 8-128 character stable operation_id. Never grants generic Ability execution, editing, deletion, plugin or site management. Do not issue a new operation_id merely to retry an uncertain result.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: false, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'title' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200],
                        'content' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 65536],
                        'operation_id' => [
                            'type' => 'string', 'minLength' => 8, 'maxLength' => 128,
                            'pattern' => '^[A-Za-z0-9_.:-]{8,128}$',
                        ],
                    ],
                    'required' => ['target_id', 'title', 'content', 'operation_id'],
                    'additionalProperties' => false,
                ],
            )
            ->addTool(
                handler: fn (string $target_id, string $ability, array $input = []): array => $this->wordpress->execute($this->principal->user($request), $target_id, $ability, $input),
                name: 'wordpress-ability-execute',
                description: 'Execute one explicitly authorized WordPress Ability with runtime safety-class enforcement.',
                annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                        'ability' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 255],
                        // MCP SDK normalizes an empty JSON object to an
                        // empty PHP array during schema validation. Admit only
                        // that zero-item array representation, not arbitrary
                        // JSON arrays, and keep the downstream object shape.
                        'input' => [
                            'anyOf' => [
                                ['type' => 'object'],
                                ['type' => 'array', 'maxItems' => 0],
                            ],
                        ],
                    ],
                    'required' => ['target_id', 'ability'],
                    'additionalProperties' => false,
                ],
            );
    }
}
