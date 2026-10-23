<?php

namespace App\Infrastructure\OAuth;

use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

final readonly class DcrClientSecretAuthenticator
{
    public function validate(ServerRequestInterface $request, string $clientId): string
    {
        $body = $request->getParsedBody();
        $parameters = is_array($body) ? $body : [];
        $secret = $parameters['client_secret'] ?? null;
        if (! is_string($secret) || strlen($secret) < 32 || strlen($secret) > 256
            || array_key_exists('client_assertion', $parameters)
            || array_key_exists('client_assertion_type', $parameters)
            || $request->getHeaderLine('Authorization') !== '') {
            throw OAuthServerException::invalidClient($request);
        }

        $stored = DB::table('oauth_dcr_clients')->where('client_id', $clientId)
            ->first(['secret_hash']);
        if ($stored === null || ! hash_equals((string) $stored->secret_hash, hash('sha256', $secret))) {
            throw OAuthServerException::invalidClient($request);
        }

        return $clientId;
    }
}
