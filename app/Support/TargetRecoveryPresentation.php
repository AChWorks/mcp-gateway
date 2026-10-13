<?php

namespace App\Support;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;

/**
 * Read-only presentation of independent evidence sources. Never infer OAuth
 * authorization from public metadata, an error timestamp or a UI action.
 */
final class TargetRecoveryPresentation
{
    /**
     * @return array{title:string,description:string,reachability:string,authorization:string,operation:string,history:?string,tone:string,canFinish:bool,canCancel:bool,needsExternalProof:bool,cancelGuidance?:string}
     */
    public static function describe(
        Target $target,
        ?object $revocationIntent = null,
        bool $refreshPending = false,
        bool $hasCredential = false,
        ?object $wpConfig = null,
        ?object $credentialMetadata = null,
        bool $oauthFlowPending = false,
    ): array {
        $checkedAt = $wpConfig === null ? null : ($wpConfig->metadata_checked_at ?? null);
        $metadataReachable = $wpConfig === null ? null : ($wpConfig->metadata_reachable ?? null);
        $timestamp = $checkedAt === null ? null : strtotime((string) $checkedAt);
        $reachability = $timestamp === null || $timestamp === false
            ? __('No recorded WordPress metadata check since this recovery version; check connectivity.')
            : match ((int) $metadataReachable) {
                1 => __('Public metadata verified at :time. Not a live heartbeat or OAuth authentication.', ['time' => date(DATE_ATOM, $timestamp)]),
                default => __('Public metadata check failed at :time. Check host and DNS compatibility.', ['time' => date(DATE_ATOM, $timestamp)]),
            };

        $historic = $target->last_error_code !== null && $target->last_failure_at !== null
            && $timestamp !== null && $timestamp !== false
            && (int) $metadataReachable === 1
            && strtotime((string) $target->last_failure_at) < $timestamp;
        $history = $target->last_error_code === null
            ? null
            : ($historic
                ? __('Earlier error before the most recent successful metadata check: :code', ['code' => $target->last_error_code])
                : __('Recorded error (diagnostic, not proof of current reachability): :code', ['code' => $target->last_error_code]));

        if ($target->connector_type !== 'wp_ai_bridge') {
            return [
                'title' => (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Connected->value
                    ? __('SSH connection last verified') : __('SSH connection needs attention'),
                'description' => __('SSH identity and login verification are separate from WordPress OAuth; a previous SSH probe is not a live connection.'),
                'reachability' => __('Inspect SSH host-key and login verification details below.'),
                'authorization' => __('SSH uses stored login credentials, not OAuth revocation.'),
                'operation' => __('No WordPress OAuth operation applies.'),
                'history' => $history,
                'tone' => (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Connected->value ? 'neutral' : 'caution',
                'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
            ];
        }

        if ($refreshPending) {
            return [
                'title' => __('WordPress refresh outcome needs reconciliation'),
                'description' => __('An OAuth token could have rotated remotely. Gateway blocks the old credential until WordPress-side authorization is resolved.'),
                'reachability' => $reachability,
                'authorization' => __('Blocked: rotating-token outcome unknown.'),
                'operation' => __('Pending OAuth refresh reconciliation.'),
                'history' => $history, 'tone' => 'caution',
                'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
            ];
        }

        if ($revocationIntent !== null) {
            $phase = (string) ($revocationIntent->phase ?? 'legacy_unknown');
            $count = max(0, (int) ($revocationIntent->token_confirmed ?? 0));
            $total = max(0, (int) ($revocationIntent->token_total ?? 0));
            $canFinish = in_array($phase, ['retryable', 'confirmed'], true);
            $accessExpiry = $credentialMetadata === null || $credentialMetadata->access_expires_at === null
                ? false : strtotime((string) $credentialMetadata->access_expires_at);
            $cancellationCandidate = $phase === 'retryable' && $count === 0;
            $canCancel = $cancellationCandidate
                && (string) ($revocationIntent->kind ?? '') === 'disconnect'
                && $total > 0 && $hasCredential && $credentialMetadata !== null
                && (string) ($revocationIntent->credential_id ?? '') === (string) $credentialMetadata->credential_id
                && (int) ($revocationIntent->generation ?? 0) === (int) $credentialMetadata->generation
                && $accessExpiry !== false && $accessExpiry > time() + 30
                && ! $oauthFlowPending;
            $cancelGuidance = null;
            if ($cancellationCandidate && ! $canCancel) {
                $cancelGuidance = $accessExpiry !== false && $accessExpiry <= time() + 30
                    ? __('Cancel is unavailable because the existing WordPress verification token has expired or expires too soon. Finish the safe disconnect, then authorize WordPress again.')
                    : __('Cancel is unavailable because Gateway cannot confirm all local verification prerequisites. Finish the safe disconnect; do not restore the existing credential.');
            }
            $operation = match ($phase) {
                'retryable' => __('Disconnect paused: next remote revoke was proven not sent; :done of :total acknowledgments recorded.', ['done' => $count, 'total' => $total]),
                'confirmed' => __('All remote token revocations were acknowledged; final local cleanup remains.'),
                'in_flight', 'verify_in_flight' => __('A request was reserved; remote completion is not safely known.'),
                'unknown' => __('Remote revocation response is ambiguous or rejected. Do not replay tokens.'),
                default => __('An older disconnect has no per-token dispatch proof. Safe cancellation or token replay is unavailable.'),
            };

            return [
                'title' => __('Disconnect incomplete'),
                'description' => $canFinish
                    ? __('Only the safe unfinished step may be completed. Do not start a separate reconnect yet.')
                    : __('The remote result cannot be proven. Follow the WordPress-side recovery instructions; credentials remain blocked.'),
                'reachability' => $reachability,
                'authorization' => __('Blocked: the existing WordPress credential cannot be used.'),
                'operation' => $operation,
                'history' => $history, 'tone' => 'caution',
                'canFinish' => $canFinish,
                'canCancel' => $canCancel,
                'cancelGuidance' => $cancelGuidance,
                'needsExternalProof' => ! $canFinish,
            ];
        }

        if ($hasCredential && (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Connected->value) {
            return [
                'title' => __('WordPress authorization stored'),
                'description' => __('Gateway has a locally connected credential. The next authenticated WordPress request verifies actual access.'),
                'reachability' => $reachability,
                'authorization' => __('Locally Connected; not a continuous remote authorization check.'),
                'operation' => __('No pending disconnect or refresh.'),
                'history' => $history, 'tone' => 'neutral',
                'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
            ];
        }

        return [
            'title' => $hasCredential ? __('WordPress authorization needs attention') : __('WordPress authorization required'),
            'description' => $hasCredential
                ? __('Stored credentials are not usable in the current state. Resolve the recorded failure before reauthorization.')
                : __('No usable WordPress credential remains. Complete the explicit authorization workflow.'),
            'reachability' => $reachability,
            'authorization' => $hasCredential ? __('Not currently connected.') : __('Not authorized.'),
            'operation' => (string) $target->getRawOriginal('connection_state') === TargetConnectionState::Pending->value
                ? __('OAuth authorization is awaiting completion.') : __('No pending disconnect or refresh.'),
            'history' => $history, 'tone' => $hasCredential ? 'caution' : 'neutral',
            'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
        ];
    }
}
