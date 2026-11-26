<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;

/** Non-secret identity captured under the existing Target lock, before a refresh or wait. */
final readonly class WpAiBridgeRefreshIdentity
{
    public string $targetId;

    public int $routeEpoch;

    public string $credentialId;

    public string $grant;

    public string $dispatch;

    public function __construct(Target $target, TargetCredential $credential, public string $intentId, public int $generation)
    {
        $this->targetId = (string) $target->getKey();
        $this->routeEpoch = (int) $target->transport_revision;
        $this->credentialId = (string) $credential->getKey();
        $this->grant = $credential->authorityFingerprint();
        $this->dispatch = $credential->dispatchFingerprint();
    }

    public function matchesIntent(object $intent): bool
    {
        return (string) $intent->target_record_id === $this->targetId
            && (string) $intent->id === $this->intentId
            && (string) $intent->credential_id === $this->credentialId
            && (int) $intent->generation === $this->generation;
    }

    public function matchesGrant(Target $target, TargetCredential $credential): bool
    {
        return (string) $target->getKey() === $this->targetId
            && (int) $target->transport_revision === $this->routeEpoch
            && (string) $credential->getKey() === $this->credentialId
            && hash_equals($this->grant, $credential->authorityFingerprint());
    }

    public function matchesMaterial(TargetCredential $credential): bool
    {
        return hash_equals($this->dispatch, $credential->dispatchFingerprint());
    }
}
