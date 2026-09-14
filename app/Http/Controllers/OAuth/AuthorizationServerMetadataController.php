<?php

namespace App\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;

final class AuthorizationServerMetadataController
{
    public function __invoke(): JsonResponse
    {
        $issuer = rtrim((string) config('oauth.issuer'), '/');

        return response()->json([
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_types_supported' => ['code'],
            'scopes_supported' => array_values((array) config('oauth.scopes')),
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            'client_id_metadata_document_supported' => true,
            'authorization_response_iss_parameter_supported' => true,
            'protected_resources' => [(string) config('oauth.resource')],
        ])->header('Cache-Control', 'public, max-age=300');
    }
}
