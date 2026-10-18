<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Models\User;

/**
 * Non-effectful, locally evidenced host-specific MCP FileParams discovery.
 *
 * Discovery does not call either downstream provider: Bridge OAuth role,
 * builder_write and upload_files remain execution-time gates before GET.
 * Do not trust clientInfo or caller parameters as an authenticated client profile.
 */
final readonly class ChatGptFileToolAvailability
{
    public function __construct(private AccessControl $access) {}

    /** @return array{wordpress:bool,ssh:bool} */
    public function modes(User $user, ?string $oauthProfile): array
    {
        $result = ['wordpress' => false, 'ssh' => false];
        if ($oauthProfile !== 'chatgpt') {
            return $result;
        }

        $wpTargets = $this->access->scopeTargets(Target::query(),
            $user, GatewayPermission::WordpressAbilitiesExecuteDestructive)
            ->where('connection_state', TargetConnectionState::Connected->value)
            ->where('operations_paused', false)
            ->whereHas('credentials', static fn ($query) => $query->where('connector_type', 'wp_ai_bridge'));

        // Both destructive (private lease) and readonly (purpose-grant preflight)
        // permissions must hold on the SAME currently connected WordPress Target.
        foreach ($wpTargets->cursor() as $target) {
            if ($this->access->allows($user, GatewayPermission::WordpressAbilitiesExecuteReadonly, $target)) {
                $result['wordpress'] = true;
                break;
            }
        }

        if (config('ssh.file_transfer.enabled', false)) {
            $result['ssh'] = $this->access->scopeTargets(Target::query(),
                $user, GatewayPermission::SshFileWrite)
                ->where('connection_state', TargetConnectionState::Connected->value)
                ->where('operations_paused', false)
                ->whereHas('sshConfig')
                ->whereHas('credentials', static fn ($query) => $query->where('connector_type', 'ssh_direct'))
                ->exists();
        }

        return $result;
    }
}
