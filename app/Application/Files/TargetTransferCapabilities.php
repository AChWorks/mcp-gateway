<?php

namespace App\Application\Files;

use App\Application\Access\AccessControl;
use App\Application\Operations\OperationalSettings;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;

/**
 * Client-neutral, permission-filtered discovery of REAL transfer interfaces.
 *
 * These are per-connector/per-mode envelopes, never a Gateway-wide file
 * ceiling. An MCP host may not support a discovered optional HTTP data plane;
 * advertising it cannot imply native attachments or model visibility.
 */
final readonly class TargetTransferCapabilities
{
    public function __construct(
        private AccessControl $access,
        private OperationalSettings $settings,
    ) {}

    /** @return array<string, mixed> */
    public function describe(User $user, Target $target): array
    {
        $description = [
            'schema_version' => 1,
            'whole_file_modes' => [],
            'native_interfaces' => [],
            'selection' => 'client_must_support_the_advertised_transport',
            'model_file_consumption_verified' => false,
        ];

        if ($target->connector_type === 'wp_ai_bridge') {
            // Stay aligned with the real WordPress execution dispatcher:
            // a client may have ONLY destructive or unclassified execution.
            $execution = [
                GatewayPermission::WordpressAbilitiesExecuteReadonly,
                GatewayPermission::WordpressAbilitiesExecuteMutating,
                GatewayPermission::WordpressAbilitiesExecuteDestructive,
                GatewayPermission::WordpressAbilitiesExecuteUnclassified,
            ];
            $grants = $this->access->allowsTargetPermissions($user, $target, [
                GatewayPermission::WordpressAbilitiesInspect, ...$execution,
            ]);
            $inspect = $grants[GatewayPermission::WordpressAbilitiesInspect->value];
            $canExecute = false;
            foreach ($execution as $permission) {
                $canExecute = $canExecute || $grants[$permission->value];
            }
            if ($inspect || $canExecute) {
                $description['native_interfaces'][] = [
                    'kind' => 'mcp_target_abilities',
                    'discovery_tool' => $inspect ? 'wordpress-abilities-read' : null,
                    'execution_tool' => $canExecute ? 'wordpress-ability-execute' : null,
                    'operation_limits' => 'per_discovered_ability_and_effective_transport',
                    'raw_whole_file_http' => false,
                ];
            }

            return $description;
        }

        if ($target->connector_type !== 'ssh_direct') {
            return $description;
        }

        $grants = $this->access->allowsTargetPermissions($user, $target, [
            GatewayPermission::SshFileRead, GatewayPermission::SshFileWrite,
        ]);
        $read = $grants[GatewayPermission::SshFileRead->value];
        $write = $grants[GatewayPermission::SshFileWrite->value];
        if ($read) {
            $description['native_interfaces'][] = [
                'kind' => 'mcp_range_read',
                'tool' => 'ssh-file-read',
                'max_raw_bytes_per_call' => 16384,
                'object_size_limit' => null,
                'snapshot' => 'size_mtime_best_effort',
            ];
        }
        if ($write) {
            $description['native_interfaces'][] = [
                'kind' => 'mcp_single_window_write',
                'tool' => 'ssh-file-write',
                'max_raw_bytes_per_call' => 16384,
                'atomic_complete_file_per_call' => true,
                'resumable' => false,
            ];
        }

        if (! config('ssh.file_transfer.enabled', false) || (! $read && ! $write)) {
            return $description;
        }

        $budget = $this->settings->sshTransferLimits();
        $prefix = '/mcp/file-transfer/ssh/'.rawurlencode($target->target_id);
        $endpoints = [];
        if ($write) {
            $endpoints['upload'] = [
                'method' => 'POST',
                'path' => $prefix.'/upload',
                'content_type' => 'application/octet-stream',
                'metadata' => 'canonical_base64url_json_x_gateway_metadata_header',
            ];
        }
        if ($read) {
            $endpoints['download'] = [
                'method' => 'POST',
                'path' => $prefix.'/download',
                'content_type' => 'application/json',
                'response_content_type' => 'application/octet-stream',
            ];
        }
        $description['whole_file_modes'][] = [
            'id' => 'ssh_https_raw_binary_v1',
            'transport' => 'authenticated_https_binary',
            'origin' => 'same_origin_as_mcp_resource',
            'auth' => 'current_oauth_access_token_bearer',
            'endpoints' => $endpoints,
            'integrity' => 'exact_bytes_and_sha256',
            'max_object_bytes' => $budget['max_bytes'],
            'max_operation_seconds' => $budget['max_seconds'],
            'bounds_scope' => 'this_synchronous_ssh_mode_only',
            'resume' => false,
            'client_requirements' => [
                'can_send_raw_binary_https_body',
                'can_receive_and_verify_binary_https_response',
            ],
            'model_attachment_handoff_verified' => false,
        ];

        return $description;
    }
}
