<?php

namespace App\Http\Controllers\OAuth;

use App\Infrastructure\OAuth\League\Entities\UserEntity;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Infrastructure\OAuth\OAuthHttpBridge;
use App\Infrastructure\OAuth\OAuthScopePolicy;
use App\Infrastructure\OAuth\OAuthServerManager;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\Response;

final readonly class AuthorizationController
{
    public function __construct(
        private OAuthServerManager $servers,
        private OAuthAuthorizationStore $authorizations,
        private OAuthHttpBridge $bridge,
        private OAuthScopePolicy $scopePolicy,
    ) {}

    public function show(Request $request): Response
    {
        if ($request->user() === null) {
            return $this->browserResponse(response()->view('oauth.authentication-required', status: 401));
        }

        try {
            $parameters = $this->authorizationParameters($request->query());
            $this->assertAuthorizationBoundary($parameters);
            $psrRequest = $this->bridge->request($request)->withQueryParams($parameters);
            $authorization = $this->servers->authorizationServer()->validateAuthorizationRequest($psrRequest);

            $redirectUri = (string) $authorization->getRedirectUri();

            return $this->browserResponse(response()->view('oauth.consent', [
                'parameters' => $parameters,
                'clientName' => $authorization->getClient()->getName(),
                'clientId' => $authorization->getClient()->getIdentifier(),
                'redirectUri' => $redirectUri,
                'scope' => implode(' ', array_map(
                    static fn ($scope): string => $scope->getIdentifier(),
                    $authorization->getScopes(),
                )),
            ]), $redirectUri);
        } catch (OAuthServerException $exception) {
            return $this->bridge->error($exception);
        }
    }

    public function complete(Request $request): Response
    {
        $user = $request->user();
        if ($user === null) {
            return $this->browserResponse(response()->view('oauth.authentication-required', status: 401));
        }

        try {
            $parameters = $this->authorizationParameters($request->all());
            $this->assertAuthorizationBoundary($parameters);
            $psrRequest = $this->bridge->request($request)->withQueryParams($parameters);
            $authorization = $this->servers->authorizationServer()->validateAuthorizationRequest($psrRequest);
            $authorization->setUser(new UserEntity((string) $user->getAuthIdentifier()));

            $approved = hash_equals('approve', (string) $request->input('decision'));
            $authorization->setAuthorizationApproved($approved);

            if ($approved) {
                $scopes = array_map(
                    static fn ($scope): string => $scope->getIdentifier(),
                    $authorization->getScopes(),
                );
                $this->authorizations->approve(
                    (int) $user->getAuthIdentifier(),
                    $authorization->getClient()->getIdentifier(),
                    (string) config('oauth.resource'),
                    $scopes,
                );
            }

            $psrResponse = $this->servers->authorizationServer()->completeAuthorizationRequest(
                $authorization,
                $this->bridge->response(),
            )->withHeader('Cache-Control', 'no-store');

            return $this->bridge->laravel($this->bridge->authorizationResponse($psrResponse));
        } catch (OAuthServerException $exception) {
            return $this->bridge->error($exception);
        }
    }

    private function browserResponse(Response $response, ?string $authorizedRedirectUri = null): Response
    {
        $formAction = "'self'";
        if ($authorizedRedirectUri !== null) {
            $redirectOrigin = $this->httpsOrigin($authorizedRedirectUri);
            if ($redirectOrigin !== null) {
                $formAction .= ' '.$redirectOrigin;
            }
        }

        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action {$formAction}; frame-ancestors 'none'; base-uri 'none'");

        return $response;
    }

    private function httpsOrigin(string $url): ?string
    {
        $parts = parse_url($url);
        if (! is_array($parts)
            || ($parts['scheme'] ?? null) !== 'https'
            || ! is_string($parts['host'] ?? null)
            || $parts['host'] === '') {
            return null;
        }

        $origin = 'https://'.$parts['host'];
        if (isset($parts['port'])) {
            $origin .= ':'.$parts['port'];
        }

        return $origin;
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array<string, string>
     */
    private function authorizationParameters(array $input): array
    {
        $limits = [
            'response_type' => 32,
            'client_id' => 1024,
            'redirect_uri' => 2048,
            'scope' => 256,
            'state' => 4096,
            'code_challenge' => 128,
            'code_challenge_method' => 32,
            'resource' => 2048,
        ];

        $parameters = [];
        foreach ($limits as $key => $maxLength) {
            if (! array_key_exists($key, $input)) {
                continue;
            }
            $value = $input[$key];
            if (! is_string($value) || strlen($value) > $maxLength) {
                throw OAuthServerException::invalidRequest($key);
            }
            $parameters[$key] = $value;
        }

        return $parameters;
    }

    /** @param array<string, string> $parameters */
    private function assertAuthorizationBoundary(array $parameters): void
    {
        if (($parameters['resource'] ?? null) !== (string) config('oauth.resource')) {
            throw OAuthServerException::invalidRequest('resource', 'The MCP resource must match the canonical Gateway MCP URI.');
        }

        $this->scopePolicy->assertAllowed($parameters['scope'] ?? null);
    }
}
