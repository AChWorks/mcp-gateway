<?php

namespace App\Http\Middleware;

use App\Infrastructure\OAuth\OAuthHttpBridge;
use App\Infrastructure\OAuth\OAuthServerManager;
use Closure;
use Illuminate\Http\Request;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\Response;

final readonly class RequireMcpAccessToken
{
    public function __construct(
        private OAuthServerManager $servers,
        private OAuthHttpBridge $bridge,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return $next($request);
        }

        if ($request->bearerToken() === null) {
            return $this->challenge(401);
        }

        try {
            $validated = $this->servers->resourceServer()->validateAuthenticatedRequest(
                $this->bridge->request($request),
            );
        } catch (OAuthServerException) {
            return $this->challenge(401, 'invalid_token');
        }

        $clientId = $validated->getAttribute('oauth_client_id');
        $scopes = $validated->getAttribute('oauth_scopes');

        if (! is_string($clientId)
            || ! hash_equals((string) config('oauth.client.id'), $clientId)) {
            return $this->challenge(401, 'invalid_token');
        }

        if (! is_array($scopes) || ! in_array((string) config('oauth.scope'), $scopes, true)) {
            return $this->challenge(403, 'insufficient_scope');
        }

        $request->attributes->set('oauth_client_id', $clientId);
        $request->attributes->set('oauth_user_id', $validated->getAttribute('oauth_user_id'));
        $request->attributes->set('oauth_access_token_id', $validated->getAttribute('oauth_access_token_id'));
        $request->attributes->set('oauth_scopes', $scopes);

        return $next($request);
    }

    private function challenge(int $status, ?string $error = null): Response
    {
        $metadata = rtrim((string) config('oauth.issuer'), '/').'/.well-known/oauth-protected-resource/mcp';
        $parts = [
            'Bearer resource_metadata="'.$metadata.'"',
            'scope="'.(string) config('oauth.scope').'"',
        ];
        if ($error !== null) {
            $parts[] = 'error="'.$error.'"';
        }

        return response('', $status)
            ->header('WWW-Authenticate', implode(', ', $parts))
            ->header('Cache-Control', 'no-store');
    }
}
