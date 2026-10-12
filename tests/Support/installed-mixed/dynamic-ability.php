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
});
