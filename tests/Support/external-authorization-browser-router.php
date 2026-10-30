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

/**
 * Test-only rendezvous, after StartSession loads its file snapshot.
 * Both GETs must overlap with a stale session writer; that writer cannot
 * finish until the HTTP test releases it after both GET responses.
 */
final class BrowserAuthorizationRaceBarrier
{
    public function handle(Request $request, Closure $next)
    {
        $race = $request->query('fixture_race');
        if ($race === null) {
            return $next($request);
        }

        abort_unless(is_string($race) && preg_match('/\A[a-f0-9]{16}\z/D', $race), 400);
        $directory = getenv('GATEWAY_BROWSER_FIXTURE_RACE_DIR');
        abort_unless(is_string($directory) && is_dir($directory), 500);
        $marker = $directory.'/'.$race.'.'.bin2hex(random_bytes(8)).'.ready';
        abort_unless(file_put_contents($marker, 'ready') !== false, 500);

        $deadline = microtime(true) + 12;
        while (count(glob($directory.'/'.$race.'.*.ready') ?: []) < 3) {
            abort_if(microtime(true) > $deadline, 500, 'Concurrent request rendezvous timed out.');
            usleep(10000);
        }

        if ($request->is('__browser__/stale-session-writer')) {
            while (! is_file($directory.'/'.$race.'.release')) {
                abort_if(microtime(true) > $deadline, 500, 'Stale session writer release timed out.');
                usleep(10000);
            }
        }

        return $next($request);
    }
}

$app = require __DIR__.'/../../bootstrap/app.php';
$kernel = $app->make(Kernel::class);
$kernel->bootstrap();

if (! $app->environment('local') || getenv('GATEWAY_BROWSER_FIXTURE') !== '1'
    || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403);
    exit;
}

// Let PHP's loopback-only server deliver real reviewed CSS/JS assets. The
// realpath boundary rejects traversal and symlink escapes from public/.
$assetPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (is_string($assetPath) && preg_match('#^/(?:css|js)/[a-zA-Z0-9._/-]+\.(?:css|js)$#D', $assetPath) === 1) {
    $publicRoot = realpath(public_path());
    $candidate = public_path(ltrim($assetPath, '/'));
    $asset = realpath($candidate);
    if (is_string($publicRoot) && is_string($asset) && is_file($asset)
        && ! is_link($candidate) && str_starts_with($asset, $publicRoot.DIRECTORY_SEPARATOR)) {
        return false;
    }
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

// The named production route is decorated only inside this disposable fixture.
$router = app('router');
$router->aliasMiddleware('fixture-authorization-race', BrowserAuthorizationRaceBarrier::class);
$handoffRoute = $router->getRoutes()->getByName('admin.targets.external-authorization');
if ($handoffRoute === null) {
    throw new RuntimeException('Expected Admin external authorization route is absent.');
}
$handoffRoute->middleware('fixture-authorization-race');

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

// Deliberately overlaps a GET with a non-handoff Admin session write,
// then saves the older in-memory handoff collection after both GETs finish.
Route::middleware(['web', 'auth', 'fixture-authorization-race'])
    ->get('/__browser__/stale-session-writer', static function (Request $request) {
        $request->session()->put('browser_fixture_unrelated_session_write', 'complete');

        return response('written');
    });

Route::middleware(['web', 'auth'])->get('/__browser__/race-release/{race}', static function (string $race) {
    abort_unless(preg_match('/\A[a-f0-9]{16}\z/D', $race), 400);
    $directory = getenv('GATEWAY_BROWSER_FIXTURE_RACE_DIR');
    abort_unless(is_string($directory) && is_dir($directory), 500);
    abort_unless(file_put_contents($directory.'/'.$race.'.release', 'release') !== false, 500);

    return response('', 204);
});

Route::middleware(['web', 'auth'])->get('/__browser__/handoff-present/{handoff}', static function (
    Request $request, string $handoff,
) {
    $pending = $request->session()->get('admin.external_authorization_handoffs', []);

    return response()->json([
        'stale_entry_present' => is_array($pending) && array_key_exists($handoff, $pending),
    ]);
})->where('handoff', '[a-f0-9]{32}');

if (getenv('GATEWAY_ADMIN_EXPERIENCE_FIXTURE') === '1') {
    require __DIR__.'/admin-experience-browser-fixtures.php';
}

$app->handleRequest(Request::capture());
