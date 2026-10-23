<?php

namespace App\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;

final class AuthorizationServerMetadataController
{
    public function __invoke(): JsonResponse
    {
        $issuer = rtrim((string) config('oauth.issuer'), '/');

        $dcrEnabled = (bool) config('oauth.dcr.registration_enabled');

        return response()->json([
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_types_supported' => ['code'],
            'scopes_supported' => array_values((array) config('oauth.scopes')),
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['private_key_jwt', 'client_secret_post'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            'revocation_endpoint_auth_methods_supported' => ['private_key_jwt', 'client_secret_post'],
            'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            'client_id_metadata_document_supported' => (bool) config('oauth.dcr.cimd_advertise'),
            ...($dcrEnabled ? ['registration_endpoint' => $issuer.'/oauth/register'] : []),
            'authorization_response_iss_parameter_supported' => true,
            'protected_resources' => [(string) config('oauth.resource')],
        ])->header('Cache-Control', 'public, max-age=300');
    }
}
