<?php

namespace App\Application\Targets;

use App\Application\Access\OperationAdmission;
use App\Application\Access\VerifiedExecutionContext;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Models\User;
use Closure;

/** One exact SSH login/operation binding, checked at each new effect. */
final readonly class SshExecutionAdmission
{
    public function __construct(
        private OperationAdmission $admission,
        private SshReverseRoutePolicy $reverseRoutes,
        private ConnectionRelayRoutes $relayRoutes,
    ) {}

    /** @return Closure():void */
    public function guard(VerifiedExecutionContext $context, User $user, Target $target,
        GatewayPermission $permission, SshTargetConfig $config, TargetCredential $credential): Closure
    {
        $fingerprint = SshTargetBinding::executionFingerprint($target, $config, $credential);
        $recordId = $target->getKey();
        $configId = $config->getKey();
        $credentialId = $credential->getKey();

        return function () use ($context, $user, $permission, $fingerprint, $recordId, $configId, $credentialId): void {
            $current = Target::query()->find($recordId);
            if ($current instanceof Target && $current->operations_paused) {
                throw new SshTargetConnectionException('target_paused');
            }
            if (! $current instanceof Target || $current->connector_type !== 'ssh_direct') {
                throw new SshTargetConnectionException('target_changed');
            }
            if ($current->getAttribute('connection_state') !== TargetConnectionState::Connected) {
                throw new SshTargetConnectionException('forbidden');
            }
            $currentConfig = SshTargetConfig::query()->find($configId);
            $currentCredential = TargetCredential::query()->find($credentialId);
            if (! $currentConfig instanceof SshTargetConfig || ! $currentCredential instanceof TargetCredential
                || ! hash_equals($fingerprint, SshTargetBinding::executionFingerprint($current, $currentConfig, $currentCredential))) {
                throw new SshTargetConnectionException('target_changed');
            }
            if (! $this->admission->allows($context, $user, $current, $permission)) {
                throw new SshTargetConnectionException($context->channel === 'deferred' ? 'authorization_revoked' : 'forbidden');
            }
            $this->reverseRoutes->forTarget($current);
            $this->relayRoutes->sshRouteForTarget($current);
        };
    }
}
