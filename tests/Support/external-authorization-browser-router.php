<?php

/**
 * Isolated local-only browser fixture for real Laravel Admin navigation.
 * Invoke explicitly with PHP's built-in server bound to 127.0.0.1 and a
 * disposable SQLite database. This router is never registered in production.
 */
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Infrastructure\Http\DnsResolver;
use App\Models\User;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Client\Request as OutboundRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../bootstrap/app.php';
$kernel = $app->make(Kernel::class);
$kernel->bootstrap();

if (! $app->environment('local') || getenv('GATEWAY_BROWSER_FIXTURE') !== '1'
    || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403);
    exit;
}

// The provider requires public HTTPS client metadata even though this fixture
// is intentionally served on loopback HTTP.
config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/targets/callback');
config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');

$app->instance(DnsResolver::class, new class implements DnsResolver
{
    public function resolve(string $host, ?int $deadlineNs = null): array
    {
        return $host === 'provider.browser.test' ? ['1.1.1.1'] : [];
    }
});

Http::preventStrayRequests();
Http::fake(static function (OutboundRequest $request) {
    if (! str_starts_with($request->url(), 'https://provider.browser.test/')) {
        return Http::response([], 404);
    }

    return match (parse_url($request->url(), PHP_URL_PATH)) {
        '/.well-known/oauth-protected-resource' => Http::response([
            'resource' => 'https://provider.browser.test/wp-json/wp-ai-bridge/v1/mcp',
            'authorization_servers' => ['https://provider.browser.test'],
            'scopes_supported' => ['mcp:use', 'offline_access'],
            'bearer_methods_supported' => ['header'],
        ]),
        '/.well-known/oauth-authorization-server' => Http::response([
            'issuer' => 'https://provider.browser.test',
            'authorization_endpoint' => 'https://provider.browser.test/wp-ai-bridge/oauth/authorize',
            'token_endpoint' => 'https://provider.browser.test/wp-json/wp-ai-bridge/v1/oauth/token',
            'revocation_endpoint' => 'https://provider.browser.test/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'client_id_metadata_document_supported' => true,
            'authorization_response_iss_parameter_supported' => true,
            'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
            'scopes_supported' => ['mcp:use', 'offline_access'],
        ]),
        default => Http::response([], 404),
    };
});

// A test-only login bootstrap, never on a production Laravel route.
Route::middleware('web')->get('/__browser__/enter', static function () {
    $owner = User::query()->firstOrCreate(['email' => 'browser-fixture@example.test'], [
        'name' => 'Local Browser Fixture',
        'password' => 'This account only exists in an isolated disposable SQLite DB.',
        'role' => 'owner',
        'target_scope_mode' => 'all',
        'access_enabled' => true,
    ]);

    if (! Target::query()->where('target_id', 'browser-wp')->exists()) {
        app(WpAiBridgeTargetRegistration::class)->register(
            'browser-wp', 'Local Browser WP', 'https://provider.browser.test',
        );
    }

    Auth::login($owner);

    return redirect()->route('admin.targets.show', ['target' => 'browser-wp']);
});

$app->handleRequest(Request::capture());
