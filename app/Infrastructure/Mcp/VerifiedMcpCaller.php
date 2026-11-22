<?php

namespace App\Infrastructure\Mcp;

use App\Models\User;
use Illuminate\Http\Request;

/** Identity from verified request middleware only, never user Tool arguments. */
final class VerifiedMcpCaller
{
    /** @return array{string,string,int} */
    public function clientIdentity(Request $request): array
    {
        $clientId = $request->attributes->get('oauth_client_id');
        $profileKey = $request->attributes->get('oauth_client_profile_key');
        $generation = $request->attributes->get('oauth_client_profile_generation');
        if (! is_string($clientId) || $clientId === ''
            || ! is_string($profileKey) || $profileKey === ''
            || ! is_int($generation) || $generation < 1) {
            abort(401);
        }

        return [$clientId, $profileKey, $generation];
    }

    public function clientHash(Request $request): string
    {
        $client = $request->attributes->get('oauth_client_id');
        $profile = $request->attributes->get('oauth_client_profile_key');
        if (! is_string($client) || $client === '' || ! is_string($profile) || $profile === '') {
            abort(401);
        }

        return hash('sha256', $profile.'\0'.$client);
    }

    public function user(Request $request): User
    {
        $user = $request->attributes->get('oauth_user');
        if (! $user instanceof User) {
            abort(401);
        }

        return $user;
    }
}
