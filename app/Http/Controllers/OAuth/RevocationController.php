<?php

namespace App\Http\Controllers\OAuth;

use App\Infrastructure\OAuth\OAuthHttpBridge;
use App\Infrastructure\OAuth\OAuthTokenRevoker;
use App\Infrastructure\OAuth\PrivateKeyJwtClientAuthenticator;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\Response;

final readonly class RevocationController
{
    public function __construct(
        private PrivateKeyJwtClientAuthenticator $clientAuthenticator,
        private OAuthTokenRevoker $revoker,
        private OAuthHttpBridge $bridge,
    ) {}

    public function __invoke(Request $request): Response
    {
        try {
            $clientId = $this->clientAuthenticator->validate(
                $this->bridge->request($request),
                [
                    (string) config('oauth.issuer'),
                    rtrim((string) config('oauth.issuer'), '/').'/oauth/revoke',
                    rtrim((string) config('oauth.issuer'), '/').'/oauth/token',
                ],
            );

            $token = $request->input('token');
            if (! is_string($token) || $token === '' || strlen($token) > 32768) {
                throw OAuthServerException::invalidRequest('token');
            }

            $this->revoker->revoke($token, $clientId);

            return response('', 200)
                ->header('Cache-Control', 'no-store')
                ->header('Pragma', 'no-cache');
        } catch (OAuthServerException $exception) {
            return $this->bridge->error($exception);
        }
    }
}
