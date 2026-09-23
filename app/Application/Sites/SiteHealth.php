<?php

namespace App\Application\Sites;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteHealthState;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use LogicException;
use Throwable;

final class SiteHealth
{
    public function state(Site $site): SiteHealthState
    {
        $connectionState = $site->getAttribute('connection_state');
        if (! $connectionState instanceof SiteConnectionState) {
            throw new LogicException('Site connection_state cast is invalid.');
        }

        if ($connectionState === SiteConnectionState::ReconnectRequired) {
            return SiteHealthState::ReconnectRequired;
        }
        if ($connectionState === SiteConnectionState::Pending) {
            return SiteHealthState::Pending;
        }
        if ($connectionState === SiteConnectionState::Reassigning) {
            return SiteHealthState::UpdatingTarget;
        }
        if ($connectionState === SiteConnectionState::Error) {
            return $this->failureState($site->last_error_code ?? $site->last_failure_code);
        }

        $latestOperationSuccess = $this->latestOperationSuccessAt($site);
        $latestEvidenceSuccess = $this->latestEvidenceSuccessAt($site);
        $latestFailure = $this->timestamp($site, 'last_failure_at');
        if ($latestFailure !== null && ($latestEvidenceSuccess === null || $latestFailure->greaterThan($latestEvidenceSuccess))) {
            return $this->failureState($site->last_failure_code);
        }

        if ($connectionState === SiteConnectionState::Disconnected) {
            return $latestOperationSuccess === null
                ? SiteHealthState::NeverConnected
                : SiteHealthState::Disconnected;
        }

        if ($latestEvidenceSuccess === null) {
            return SiteHealthState::Unknown;
        }

        return $latestEvidenceSuccess->lessThan($this->staleCutoff())
            ? SiteHealthState::Stale
            : SiteHealthState::Healthy;
    }

    public function staleCutoff(): CarbonImmutable
    {
        $hours = max(1, (int) config('bridge.health.stale_after_hours', 24));

        return CarbonImmutable::instance(now())->subHours($hours);
    }

    public function latestEvidenceSuccessAt(Site $site): ?CarbonImmutable
    {
        $latest = $this->latestOperationSuccessAt($site);
        $lastTested = $site->last_error_code === null
            ? $this->timestamp($site, 'last_tested_at')
            : null;

        if ($latest === null) {
            return $lastTested;
        }
        if ($lastTested === null) {
            return $latest;
        }

        return $lastTested->greaterThan($latest) ? $lastTested : $latest;
    }

    private function latestOperationSuccessAt(Site $site): ?CarbonImmutable
    {
        $lastSuccess = $this->timestamp($site, 'last_success_at');
        $connectedAt = $this->timestamp($site, 'connected_at');

        if ($lastSuccess === null) {
            return $connectedAt;
        }
        if ($connectedAt === null) {
            return $lastSuccess;
        }

        return $lastSuccess->greaterThan($connectedAt) ? $lastSuccess : $connectedAt;
    }

    public function recordOperationSuccess(Site $site): void
    {
        $this->persistOperationEvidence($site, [
            'last_success_at' => now(),
        ], 'success');
    }

    public function recordOperationFailure(Site $site, string $code): void
    {
        $safeCode = $this->safeFailureCode($code);
        $this->persistOperationEvidence($site, [
            'last_failure_at' => now(),
            'last_failure_code' => $safeCode,
        ], 'failure', $safeCode);
    }

    private function failureState(?string $code): SiteHealthState
    {
        return match ($code) {
            'network_failure', 'tls_failure', 'remote_failure' => SiteHealthState::Unreachable,
            'missing_bridge', 'incompatible_metadata', 'protocol_error', 'invalid_json' => SiteHealthState::Incompatible,
            'downstream_auth', 'invalid_grant', 'missing_credential', 'credential_target_mismatch', 'credential_unavailable' => SiteHealthState::ReconnectRequired,
            'outcome_unknown' => SiteHealthState::Unknown,
            null, '' => SiteHealthState::Unknown,
            default => SiteHealthState::Failed,
        };
    }

    /** @param array<string,mixed> $attributes */
    private function persistOperationEvidence(
        Site $site,
        array $attributes,
        string $kind,
        ?string $errorCode = null,
    ): void {
        try {
            Site::query()->whereKey($site->getKey())->update($attributes);
            $site->forceFill($attributes);
        } catch (Throwable) {
            try {
                Log::warning('Site health evidence persistence failed.', [
                    'site_id' => $site->site_id,
                    'evidence_kind' => $kind,
                    'error_code' => $errorCode,
                ]);
            } catch (Throwable) {
                // Diagnostic persistence must never change a routed operation result.
            }
        }
    }

    private function timestamp(Site $site, string $attribute): ?CarbonImmutable
    {
        $value = $site->getAttribute($attribute);
        if ($value === null) {
            return null;
        }
        if (! $value instanceof CarbonImmutable) {
            throw new LogicException(sprintf('Site %s cast is invalid.', $attribute));
        }

        return $value;
    }

    private function safeFailureCode(string $code): string
    {
        $safe = strtolower(preg_replace('/[^a-zA-Z0-9_.-]+/', '_', $code) ?? 'failure');
        $safe = trim($safe, '_');

        return Str::limit($safe !== '' ? $safe : 'failure', 64, '');
    }
}
