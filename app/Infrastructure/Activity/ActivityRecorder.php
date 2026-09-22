<?php

namespace App\Infrastructure\Activity;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

final class ActivityRecorder
{
    public function record(
        string $correlationId,
        string $operation,
        string $outcome,
        ?string $siteId = null,
        ?string $errorCode = null,
    ): void {
        [$correlationId, $operation, $outcome, $siteId, $errorCode] = $this->normalized(
            $correlationId,
            $operation,
            $outcome,
            $siteId,
            $errorCode,
        );

        try {
            $this->persist($correlationId, $operation, $outcome, $siteId, $errorCode);
        } catch (Throwable) {
            // Activity persistence must never change the authoritative outcome of a
            // routed operation, especially after a remote mutation may have executed.
            try {
                Log::warning('Gateway activity persistence failed.', [
                    'correlation_id' => $correlationId,
                    'operation' => $operation,
                    'site_id' => $siteId,
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
        ?string $siteId = null,
        ?string $errorCode = null,
    ): void {
        $this->persist(...$this->normalized(
            $correlationId,
            $operation,
            $outcome,
            $siteId,
            $errorCode,
        ));
    }

    /**
     * @return array{string,string,string,?string,?string}
     */
    private function normalized(
        string $correlationId,
        string $operation,
        string $outcome,
        ?string $siteId,
        ?string $errorCode,
    ): array {
        return [
            $this->correlationId($correlationId),
            $this->safeIdentifier($operation, 128) ?? 'unknown',
            $this->safeIdentifier($outcome, 32) ?? 'unknown',
            $this->safeIdentifier($siteId, 128),
            $this->safeIdentifier($errorCode, 64),
        ];
    }

    private function persist(
        string $correlationId,
        string $operation,
        string $outcome,
        ?string $siteId,
        ?string $errorCode,
    ): void {
        [$actorType, $actorId, $clientHash] = $this->actor();

        DB::table('activity_events')->insert([
            'id' => (string) Str::ulid(),
            'correlation_id' => $correlationId,
            'actor_type' => $actorType,
            'actor_id' => $actorId,
            'client_id_hash' => $clientHash,
            'site_id' => $siteId,
            'operation' => $operation,
            'outcome' => $outcome,
            'error_code' => $errorCode,
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
