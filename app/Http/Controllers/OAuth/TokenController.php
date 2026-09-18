<?php

namespace App\Http\Controllers\OAuth;

use App\Infrastructure\OAuth\League\ResponseTypes\RecoverableBearerTokenResponse;
use App\Infrastructure\OAuth\OAuthHttpBridge;
use App\Infrastructure\OAuth\OAuthScopePolicy;
use App\Infrastructure\OAuth\OAuthServerManager;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\Response;

final readonly class TokenController
{
    public function __construct(
        private OAuthServerManager $servers,
        private OAuthHttpBridge $bridge,
        private OAuthScopePolicy $scopePolicy,
    ) {}

    public function __invoke(Request $request): Response
    {
        try {
            $resource = $request->input('resource');
            if (! is_string($resource) || ! hash_equals((string) config('oauth.resource'), $resource)) {
                throw OAuthServerException::invalidRequest(
                    'resource',
                    'The token request must target the canonical Gateway MCP resource.',
                );
            }

            $this->scopePolicy->assertAllowed($request->input('scope'));

            $grantType = $request->input('grant_type');
            if (! is_string($grantType) || ! in_array($grantType, ['authorization_code', 'refresh_token'], true)) {
                throw OAuthServerException::unsupportedGrantType();
            }

            $psrResponse = $this->servers->authorizationServer()->respondToAccessTokenRequest(
                $this->bridge->request($request),
                $this->bridge->response(),
            );

            if ($psrResponse->getHeaderLine(RecoverableBearerTokenResponse::INTERNAL_RECOVERY_HEADER) === '1') {
                $request->attributes->set('oauth_token_recovered', true);
                $psrResponse = $psrResponse->withoutHeader(RecoverableBearerTokenResponse::INTERNAL_RECOVERY_HEADER);
            }

            $psrResponse = $psrResponse
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');

            return $this->bridge->laravel($psrResponse);
        } catch (OAuthServerException $exception) {
            $request->attributes->set('oauth_token_error_code', $exception->getErrorType());

            return $this->bridge->error($exception);
        }
    }
}
