<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Request;
use McpGatewayUpdate\WebUpdater;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Throwable;

$basePath = dirname(__DIR__, 2);
$packagePath = $basePath.'/update';
$autoloadPath = $basePath.'/vendor/autoload.php';
$updaterPath = $packagePath.'/WebUpdater.php';
$statePath = $basePath.'/storage/app/private/update-state.json';

function updaterEscape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function updaterIsHttps(array $server): bool
{
    $https = strtolower((string) ($server['HTTPS'] ?? ''));
    if ($https !== '' && $https !== 'off') {
        return true;
    }

    if ((string) ($server['SERVER_PORT'] ?? '') === '443') {
        return true;
    }

    $forwarded = strtolower(trim(explode(',', (string) ($server['HTTP_X_FORWARDED_PROTO'] ?? ''))[0] ?? ''));

    return $forwarded === 'https';
}

function updaterRender(string $title, string $body, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>'.updaterEscape($title).'</title><style>';
    echo ':root{font-family:system-ui,sans-serif;color-scheme:light dark}body{margin:0;background:#f4f5f7;color:#1f2937}main{max-width:760px;margin:40px auto;padding:0 20px 48px}.card{background:#fff;border:1px solid #d9dde3;border-radius:12px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,.05)}h1{margin-top:0}p,li{line-height:1.55}.checks{list-style:none;padding:0}.checks li{padding:4px 0}.ok{color:#087f23}.error{color:#b42318}.notice{padding:12px 14px;border-radius:8px;background:#fff6e5;margin:14px 0}.success{padding:16px;border-radius:8px;background:#e9f8ee;color:#116329}button{padding:11px 18px;border:0;border-radius:8px;background:#111827;color:#fff;font-weight:700;cursor:pointer}code{background:#eef0f3;padding:2px 5px;border-radius:4px}@media(prefers-color-scheme:dark){body{background:#111827;color:#e5e7eb}.card{background:#1f2937;border-color:#374151}.notice{background:#3b2f16}.success{background:#12351f;color:#9be4ae}code{background:#374151}}';
    echo '</style></head><body><main><div class="card"><h1>'.updaterEscape($title).'</h1>'.$body.'</div></main></body></html>';
    exit;
}

function updaterCookie(string $value): void
{
    setcookie('mcp_gateway_update_session', $value, [
        'expires' => time() + 1800,
        'path' => '/update/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function updaterClearCookie(): void
{
    setcookie('mcp_gateway_update_session', '', [
        'expires' => time() - 3600,
        'path' => '/update/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

if (! updaterIsHttps($_SERVER)) {
    updaterRender(
        'MCP Gateway Update',
        '<p class="error">HTTPS is required before the browser updater can run.</p>',
        403,
    );
}

if (! is_file($autoloadPath)) {
    updaterRender('MCP Gateway Update', '<p class="error">The existing Gateway runtime is incomplete: <code>vendor/autoload.php</code> is missing.</p>', 503);
}

require $autoloadPath;

if (! is_file($updaterPath)) {
    updaterRender('MCP Gateway Update', '<p>This updater is no longer available. If the update completed, return to the administrator panel.</p><p><a href="/admin">Open administrator panel</a></p>', 410);
}

require $updaterPath;

$browserToken = is_string($_COOKIE['mcp_gateway_update_session'] ?? null)
    ? $_COOKIE['mcp_gateway_update_session']
    : '';
$action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';
$continuation = is_string($_POST['continuation'] ?? null) ? $_POST['continuation'] : '';

$app = require $basePath.'/bootstrap/app.php';
$updater = new WebUpdater($basePath, $packagePath);

// After the first phase the application is in maintenance mode. Finish the
// update directly with the private browser token + one-time continuation token.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'finish') {
    try {
        $app->make(ConsoleKernel::class)->bootstrap();
        $result = $updater->finish($browserToken, $continuation);
        updaterClearCookie();

        $warning = $result['cleanup_warning'] === null
            ? '<p>The temporary updater, staging payload, and canonical uploaded update ZIP were cleaned up automatically.</p>'
            : '<div class="notice">'.updaterEscape($result['cleanup_warning']).'</div>';

        updaterRender(
            'MCP Gateway Updated',
            '<div class="success"><strong>Update complete.</strong><p>MCP Gateway '.updaterEscape($result['from']).' → '.updaterEscape($result['to']).' is installed and the application is live.</p></div>'.$warning.'<p><a href="/admin">Open administrator panel</a></p>',
        );
    } catch (Throwable $exception) {
        updaterRender(
            'MCP Gateway Update Needs Attention',
            '<p class="error">'.updaterEscape($exception->getMessage()).'</p><div class="notice">Do not re-extract or start another update. The application is intentionally left in maintenance mode when database migration may have started. Use the retained private code backup for operator-directed recovery.</div>',
            500,
        );
    }
}

// If the first response was interrupted after managed files were replaced,
// allow the same browser session to resume the post-update phase safely.
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $browserToken !== '') {
    $pending = $updater->pendingContinuation($browserToken);
    if ($pending !== null) {
        updaterRender(
            'Resume MCP Gateway Update',
            '<p>The application files are staged and ready for the final update checks.</p><form method="post"><input type="hidden" name="action" value="finish"><input type="hidden" name="continuation" value="'.updaterEscape($pending).'"><button type="submit">Continue update</button></form>',
        );
    }

    $failed = $updater->failedState($browserToken);
    if ($failed !== null) {
        updaterRender(
            'MCP Gateway Update Needs Attention',
            '<p class="error">A previous update reached the database-migration boundary and did not complete safely.</p><div class="notice">Do not start another update. The Gateway remains in maintenance mode and the private code backup is retained for recovery.</div>',
            500,
        );
    }
}

// Normal preflight/start uses the existing Laravel administrator session. We
// run an internal authenticated /admin request so v1.1.2 needs no new route.
try {
    $httpKernel = $app->make(HttpKernel::class);
    $server = $_SERVER;
    $server['REQUEST_URI'] = '/admin';
    $server['PATH_INFO'] = '/admin';
    $authRequest = Request::create('/admin', 'GET', [], $_COOKIE, [], $server);
    $authResponse = $httpKernel->handle($authRequest);

    if ($authResponse instanceof RedirectResponse || $authResponse->isRedirection()) {
        if ($authRequest->hasSession()) {
            $authRequest->session()->put('url.intended', '/update/');
            $authRequest->session()->save();
        }
        $httpKernel->terminate($authRequest, $authResponse);
        header('Location: /admin/login', true, 302);
        exit;
    }

    if ($authResponse->getStatusCode() !== 200 || ! $authRequest->hasSession()) {
        $httpKernel->terminate($authRequest, $authResponse);
        updaterRender('MCP Gateway Update', '<p class="error">Administrator authentication could not be verified.</p>', 403);
    }

    $csrf = (string) $authRequest->session()->token();
    $httpKernel->terminate($authRequest, $authResponse);
    $app->make(ConsoleKernel::class)->bootstrap();
} catch (Throwable $exception) {
    updaterRender('MCP Gateway Update', '<p class="error">Could not initialize the authenticated update session.</p>', 500);
}

if ($browserToken === '' || ! preg_match('/^[a-f0-9]{64}$/', $browserToken)) {
    $browserToken = bin2hex(random_bytes(32));
    updaterCookie($browserToken);
}

try {
    $info = $updater->inspect();
} catch (Throwable $exception) {
    updaterRender('MCP Gateway Update', '<p class="error">'.updaterEscape($exception->getMessage()).'</p>', 400);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'start') {
    $postedCsrf = is_string($_POST['_token'] ?? null) ? $_POST['_token'] : '';
    if ($postedCsrf === '' || ! hash_equals($csrf, $postedCsrf)) {
        updaterRender('MCP Gateway Update', '<p class="error">The administrator session expired. Reload this page and try again.</p>', 419);
    }

    try {
        $result = $updater->stage($browserToken);
        header('Content-Type: text/html; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('X-Robots-Tag: noindex, nofollow, noarchive');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Continuing MCP Gateway Update</title></head><body>';
        echo '<p>Application files are installed. Continuing database and health checks…</p>';
        echo '<form id="continue-update" method="post" action="/update/"><input type="hidden" name="action" value="finish"><input type="hidden" name="continuation" value="'.updaterEscape($result['continuation']).'"></form>';
        echo '<script>document.getElementById("continue-update").submit();</script><noscript><button form="continue-update" type="submit">Continue update</button></noscript>';
        echo '</body></html>';
        exit;
    } catch (Throwable $exception) {
        updaterRender('MCP Gateway Update Failed', '<p class="error">'.updaterEscape($exception->getMessage()).'</p><p>The live application was restored automatically because database migration had not started.</p>', 500);
    }
}

$checks = '';
foreach ($info['checks'] as $label => $passed) {
    $checks .= '<li class="'.($passed ? 'ok' : 'error').'">'.($passed ? '✓' : '✗').' '.updaterEscape($label).'</li>';
}

updaterRender(
    'Update MCP Gateway',
    '<p>This temporary updater will upgrade the current Gateway without SSH, Git, or Composer.</p><p><strong>Installed:</strong> '.updaterEscape($info['installed']).'<br><strong>Target:</strong> '.updaterEscape($info['target']).'</p><h2>Preflight</h2><ul class="checks">'.$checks.'</ul><div class="notice">The existing <code>.env</code> and persistent <code>storage/</code> are preserved. A private code backup is retained before any managed files are replaced.</div><form method="post"><input type="hidden" name="_token" value="'.updaterEscape($csrf).'"><input type="hidden" name="action" value="start"><button type="submit">Update MCP Gateway</button></form>',
);
