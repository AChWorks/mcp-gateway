<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * Evidence-bounded Admin status. Host readiness is not a network probe,
 * and neither a SOCKS greeting nor host evidence authenticates a Target.
 */
enum ConnectionRelayOperationalState: string
{
    case Draft = 'draft';
    case NeedsSetup = 'needs_setup';
    case Ready = 'ready';
    case Enabled = 'enabled';
    case Degraded = 'degraded';
    case CleanupRequired = 'cleanup_required';

    public static function assess(ConnectionRelay $relay, bool $hostReady, bool $deletionFenced): self
    {
        if ($relay->enabled && ($deletionFenced || ! $hostReady)) {
            return self::Degraded;
        }
        if ($deletionFenced) {
            return self::CleanupRequired;
        }
        if ($relay->enabled) {
            return self::Enabled;
        }
        if ($hostReady) {
            return self::Ready;
        }

        // "Draft" describes the initial DB lifecycle, NOT proof that no
        // separate root-owned host resources exist.
        if ((int) $relay->configuration_revision === 1 && (int) $relay->lifecycle_revision === 1) {
            return self::Draft;
        }

        return self::NeedsSetup;
    }

    public function label(): string
    {
        return match ($this) {
            self::Draft => __('Draft — host unverified'),
            self::NeedsSetup => __('Needs setup or re-verification'),
            self::Ready => __('Ready — host evidence current'),
            self::Enabled => __('Enabled — host evidence current'),
            self::Degraded => __('Degraded — routing blocked'),
            self::CleanupRequired => __('Cleanup required — finalize removal'),
        };
    }

    public function nextAction(): string
    {
        return match ($this) {
            self::Draft => __('The registration is saved, but privileged host setup and attestation have not been verified. Do not assume host resources are absent.'),
            self::NeedsSetup => __('Gateway host Setup can stage a dedicated SSH identity, supervised service and local ACL through an explicitly root-run operator command. Staging never issues readiness. Keep this Relay disabled until the Iran-side controls, PHP UID isolation and independently issued host evidence are verified. Bound Targets never fall back to Direct.'),
            self::Ready => __('You can enable this Relay deliberately. Host evidence does not prove the SOCKS listener or any Target identity.'),
            self::Enabled => __('Check the local SOCKS5 listener, then separately authenticate each Target. Current host evidence alone does not prove a working route.'),
            self::Degraded => __('Host evidence is missing or stale, or this record conflicts with a permanent deletion fence. Bound Target operations fail closed; disable this Relay now. Retry the exact scoped Gateway Setup command only for a matching staged configuration; restoration requires independently verified host work and fresh readiness evidence; a permanently fenced record must never be reprovisioned.'),
            self::CleanupRequired => __('A permanent deletion fence is present. Renew expired retirement evidence with the scoped seal-delete command, then confirm record deletion. Do not reprovision this record.'),
        };
    }
}
