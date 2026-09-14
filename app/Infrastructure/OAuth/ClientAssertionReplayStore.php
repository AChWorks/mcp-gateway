<?php

namespace App\Infrastructure\OAuth;

use DateTimeImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

final class ClientAssertionReplayStore
{
    public function remember(string $clientId, string $jti, DateTimeImmutable $expiresAt): bool
    {
        DB::table('oauth_client_assertions')
            ->where('expires_at', '<', now()->subMinute())
            ->delete();

        try {
            DB::table('oauth_client_assertions')->insert([
                'client_id' => $clientId,
                'jti_hash' => hash('sha256', $jti),
                'expires_at' => $expiresAt,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (QueryException $exception) {
            if (in_array((string) $exception->getCode(), ['23000', '19'], true)) {
                return false;
            }

            throw $exception;
        }

        return true;
    }
}
