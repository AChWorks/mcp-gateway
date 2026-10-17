<?php

namespace App\Infrastructure\Activity;

use App\Domain\Targets\Target;
use App\Support\OperationDiagnostics;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

final class ActivityRecorder
{
    /** @param array<string,mixed> $diagnostics */
    public function record(
        string $correlationId,
        string $operation,
        string $outcome,
        ?Target $target = null,
        ?string $errorCode = null,
        array $diagnostics = [],
    ): void {
        [$correlationId, $operation, $outcome, $target, $errorCode] = $this->normalized(
            $correlationId,
            $operation,
            $outcome,
            $target,
            $errorCode,
        );

        // Preserve observed errors with selective credential redaction in the
        // existing Activity store. Unknown effects remain non-retryable.
        try {
            $safeDetails = in_array($outcome, ['failure', 'unknown'], true)
                ? OperationDiagnostics::safeContext([
                    ...$diagnostics,
                    ...($outcome === 'unknown' ? ['retry_safe' => false] : []),
                ]) : [];
            $this->persist($correlationId, $operation, $outcome, $target, $errorCode, $safeDetails);
            // One shared operational diagnostic path across WordPress, SSH,
            // inventory, MCP and file handlers; no raw inputs or tool outputs.
            // Routine rejected/invalid requests remain in Activity only so
            // hostile traffic cannot amplify the daily server log.
            if (in_array($outcome, ['failure', 'unknown'], true)
                && ! in_array($errorCode, ['target_not_found', 'forbidden', 'invalid_input', 'mcp_principal_rate_limited', 'mcp_edge_rate_limited'], true)) {
                OperationDiagnostics::failure($operation, $errorCode ?? 'operation_failed', $target, [
                    ...$diagnostics,
                    'retry_safe' => $outcome === 'unknown' ? false : ($diagnostics['retry_safe'] ?? null),
                ], $correlationId);
            }
        } catch (Throwable) {
            // Activity persistence must never change the authoritative outcome of a
            // routed operation, especially after a remote mutation may have executed.
            try {
                Log::warning('Gateway activity persistence failed.', [
                    'correlation_id' => $correlationId,
                    'operation' => $operation,
                    'target_id' => $target?->target_id,
                    'target_record_id' => $target?->getKey(),
                    'connector_type_snapshot' => $target?->connector_type,
                    'outcome' => $outcome,
                    'error_code' => $errorCode,
                ]);
            } catch (Throwable) {
                // Diagnostics are best-effort and must not change the routed result.
            }
        }
    }

    public function recordRequired(
        string $correlationId,
        string $operation,
        string $outcome,
        ?Target $target = null,
        ?string $errorCode = null,
    ): void {
        $this->persist(...$this->normalized(
            $correlationId,
            $operation,
            $outcome,
            $target,
            $errorCode,
        ));
    }

    /**
     * @return array{string,string,string,?Target,?string}
     */
    private function normalized(
        string $correlationId,
        string $operation,
        string $outcome,
        ?Target $target,
        ?string $errorCode,
    ): array {
        return [
            $this->correlationId($correlationId),
            $this->safeIdentifier($operation, 128) ?? 'unknown',
            $this->safeIdentifier($outcome, 32) ?? 'unknown',
            $target,
            $this->safeIdentifier($errorCode, 64),
        ];
    }

    /** @param array<string,mixed> $safeDetails */
    private function persist(
        string $correlationId,
        string $operation,
        string $outcome,
        ?Target $target,
        ?string $errorCode,
        array $safeDetails = [],
    ): void {
        [$actorType, $actorId, $clientHash] = $this->actor();
        $request = app()->bound('request') ? app('request') : null;
        $profileKey = $request?->attributes->get('oauth_client_profile_key');

        DB::table('activity_events')->insert([
            'id' => (string) Str::ulid(),
            'correlation_id' => $correlationId,
            'actor_type' => $actorType,
            'actor_id' => $actorId,
            'client_id_hash' => $clientHash,
            'client_profile_key' => $clientHash !== null && is_string($profileKey)
                && preg_match('/^[a-z][a-z0-9_-]{0,47}$/D', $profileKey) === 1
                ? $profileKey : null,
            'target_id' => $target?->target_id,
            'target_record_id' => $target?->getKey(),
            'connector_type_snapshot' => $target?->connector_type,
            'operation' => $operation,
            'outcome' => $outcome,
            'error_code' => $errorCode,
            'diagnostic_context' => $safeDetails === [] ? null
                : json_encode($safeDetails, JSON_THROW_ON_ERROR),
            'created_at' => now(),
        ]);
    }

    /** @return array{string,?string,?string} */
    private function actor(): array
    {
        if (! app()->bound('request')) {
            return ['system', null, null];
        }

        $request = app('request');
        $clientId = $request->attributes->get('oauth_client_id');
        $clientHash = is_string($clientId) && $clientId !== ''
            ? hash('sha256', $clientId)
            : null;

        $oauthUserId = $request->attributes->get('oauth_user_id');
        if (is_int($oauthUserId) || is_string($oauthUserId)) {
            $actorId = $this->safeIdentifier((string) $oauthUserId, 128);
            if ($actorId !== null) {
                return ['oauth_user', $actorId, $clientHash];
            }
        }

        $user = $request->user();
        if ($user !== null) {
            $actorId = $this->safeIdentifier((string) $user->getAuthIdentifier(), 128);

            return ['administrator', $actorId, $clientHash];
        }

        return ['anonymous', null, $clientHash];
    }

    private function correlationId(string $value): string
    {
        return Str::isUuid($value) ? $value : (string) Str::uuid();
    }

    private function safeIdentifier(?string $value, int $max): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);
        if ($value === '') {
            return null;
        }

        $value = preg_replace('/[^A-Za-z0-9._:@\/-]+/', '_', $value) ?? '';
        $value = trim($value, '_');
        if ($value === '') {
            return null;
        }

        return mb_substr($value, 0, $max);
    }
}
