<?php

namespace App\Infrastructure\Mcp;

use App\Application\Targets\ArvanApiOperations;
use Illuminate\Http\Request;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server\Builder;

/** Registers a focused, ordered portion of the existing MCP tool catalog. */
final readonly class ArvanMcpToolRegistrar
{
    public function __construct(
        private ArvanApiOperations $arvan,
        private VerifiedMcpCaller $principal,
    ) {}

    public function register(Builder $builder, Request $request): void
    {
        $builder->addTool(
            handler: fn (
                string $target_id, int $offset = 0, int $limit = 20, ?string $search = null,
            ): array => $this->arvan->catalog($this->principal->user($request), $target_id, $offset, $limit, $search),
            name: 'arvan-api-catalog',
            description: 'Discover documented ArvanCloud API methods and parameter schemas for an explicitly authorized Target. Public OpenAPI is untrusted reference data, not a grant. If a compatible API adds endpoints, no new Gateway Tool is required.',
            annotations: new ToolAnnotations(readOnlyHint: true, destructiveHint: false, openWorldHint: true),
            inputSchema: [
                'type' => 'object',
                'properties' => [
                    'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                    'offset' => ['type' => 'integer', 'minimum' => 0, 'default' => 0],
                    'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 20],
                    'search' => ['type' => 'string', 'maxLength' => 255],
                ],
                'required' => ['target_id'],
                'additionalProperties' => false,
            ],
        )->addTool(
            handler: fn (
                string $target_id, string $method, string $path, array $query = [], ?string $body_json = null,
                ?string $body_text = null, ?string $content_type = null,
                array $form_fields = [], array $form_files = [], ?string $accept = null,
            ): array => $this->arvan->execute(
                $this->principal->user($request), $target_id, $method, $path, $query, $body_json,
                $body_text, $content_type, $form_fields, $form_files, $accept,
            ),
            name: 'arvan-api-request',
            description: 'Execute a compatible ArvanCloud API method on ONE registered Target; never supply a host, absolute URL, Authorization header or key. For request bodies choose one: body_json (optional content_type for JSON Patch/vendor JSON), body_text with content_type (e.g. Kubernetes YAML), or form_fields/form_files for URL-encoded/multipart fields and base64 file parts. For multipart form_fields, set content_type=multipart/form-data. Only an optional validated Accept media type is client-selectable as a header. GET/HEAD/OPTIONS use arvan.api.read, POST/PUT/PATCH write, DELETE destructive, others unclassified. Provider-side business effects may be destructive even on POST. Mutations with uncertain outcomes must be reconciled before retry; obtain user confirmation for high-impact changes.',
            annotations: new ToolAnnotations(readOnlyHint: false, destructiveHint: true, openWorldHint: true),
            inputSchema: [
                'type' => 'object',
                'properties' => [
                    'target_id' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 64],
                    'method' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 32],
                    'path' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 1024],
                    'query' => [
                        'anyOf' => [
                            ['type' => 'object'],
                            ['type' => 'array', 'maxItems' => 0],
                        ],
                    ],
                    'body_json' => ['type' => 'string'],
                    'body_text' => ['type' => 'string'],
                    'content_type' => ['type' => 'string'],
                    'accept' => ['type' => 'string'],
                    'form_fields' => [
                        'anyOf' => [
                            ['type' => 'object'],
                            ['type' => 'array', 'maxItems' => 0],
                        ],
                    ],
                    'form_files' => [
                        'type' => 'array',
                        'items' => [
                            'type' => 'object',
                            'properties' => [
                                'name' => ['type' => 'string'],
                                'filename' => ['type' => 'string'],
                                'content_base64' => ['type' => 'string'],
                                'content_type' => ['type' => 'string'],
                            ],
                            'required' => ['name', 'filename', 'content_base64'],
                            'additionalProperties' => false,
                        ],
                    ],
                ],
                'required' => ['target_id', 'method', 'path'],
                'additionalProperties' => false,
            ],
        );
    }
}
