<?php

/**
 * Disposable WordPress mu-plugin added during one already-connected MCP session.
 * This file is not part of the WP AI Bridge source tree.
 */
add_action('wp_abilities_api_categories_init', static function (): void {
    wp_register_ability_category('gateway-mixed-test', [
        'label' => 'Disposable Mixed Acceptance',
        'description' => 'Read-only, isolated provider acceptance.',
    ]);
});
add_action('wp_abilities_api_init', static function (): void {
    foreach (['dynamic-read' => true, 'denied-read' => false] as $name => $allowed) {
        wp_register_ability('gateway-mixed-test/'.$name, [
            'label' => 'Gateway mixed test '.$name,
            'description' => 'Read-only fixture with a new, previously unknown provider name.',
            'category' => 'gateway-mixed-test',
            'input_schema' => ['type' => 'object', 'properties' => (object) []],
            'output_schema' => ['type' => 'object', 'properties' => [
                'origin' => ['type' => 'string'],
                'marker' => ['type' => 'string'],
            ]],
            'permission_callback' => static fn (): bool => $allowed && current_user_can('read'),
            'execute_callback' => static fn (): array => [
                'origin' => 'installed-wordpress',
                'marker' => $name,
            ],
            'meta' => [
                'mcp' => ['public' => true, 'type' => 'tool'],
                'annotations' => ['readonly' => true, 'destructive' => false, 'idempotent' => true],
            ],
        ]);
    }
    wp_register_ability('gateway-mixed-test/digest-read', [
        'label' => 'Disposable payload digest',
        'description' => 'Read-only digest of the actual received UTF-8 input; no persistence.',
        'category' => 'gateway-mixed-test',
        'input_schema' => ['type' => 'object', 'properties' => [
            'payload' => ['type' => 'string'],
        ], 'required' => ['payload'], 'additionalProperties' => false],
        'output_schema' => ['type' => 'object', 'properties' => [
            'bytes' => ['type' => 'integer'],
            'sha256' => ['type' => 'string'],
            'principal_id' => ['type' => 'integer'],
        ]],
        'permission_callback' => static fn (): bool => current_user_can('read'),
        'execute_callback' => static fn (array $input): array => [
            'bytes' => strlen($input['payload']),
            'sha256' => hash('sha256', $input['payload']),
            'principal_id' => get_current_user_id(),
        ],
        'meta' => [
            'mcp' => ['public' => true, 'type' => 'tool'],
            'annotations' => ['readonly' => true, 'destructive' => false, 'idempotent' => true],
        ],
    ]);
});
