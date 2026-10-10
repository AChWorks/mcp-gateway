<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Request;
use McpGatewayUpdate\UpdateBusyException;
use McpGatewayUpdate\WebUpdater;
use Symfony\Component\HttpFoundation\RedirectResponse;

$basePath = dirname(__DIR__, 2);
$packagePath = $basePath.'/update';
$autoloadPath = $basePath.'/vendor/autoload.php';
$updaterPath = $packagePath.'/WebUpdater.php';

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

    // The primary deployment target terminates HTTPS in OpenLiteSpeed and
    // therefore sets HTTPS/SERVER_PORT directly. The forwarded-proto fallback
    // is accepted only from loopback for local reverse-proxy/test setups so an
    // arbitrary remote client cannot spoof HTTPS with a request header.
    $remoteAddress = (string) ($server['REMOTE_ADDR'] ?? '');
    if (! in_array($remoteAddress, ['127.0.0.1', '::1'], true)) {
        return false;
    }

    $forwarded = strtolower(trim(explode(',', (string) ($server['HTTP_X_FORWARDED_PROTO'] ?? ''))[0] ?? ''));

    return $forwarded === 'https';
}

function updaterRender(string $title, string $body, int $status = 200, ?string $script = null): never
{
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    $interactive = $script === null ? '' : " script-src 'unsafe-inline'; connect-src 'self';";
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';".$interactive." form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>'.updaterEscape($title).'</title><style>';
    echo ':root{font-family:system-ui,-apple-system,sans-serif;color-scheme:light dark}*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;min-height:100vh;background:#f2f5f9;color:#1e293b}main{max-width:820px;margin:clamp(20px,5vw,72px) auto;padding:0 18px 60px}.card{background:#fff;border:1px solid #dbe3ee;border-radius:18px;padding:clamp(22px,4vw,38px);box-shadow:0 16px 50px rgba(17,42,77,.08)}.brand{display:flex;align-items:center;gap:10px;font-size:.85rem;font-weight:750;letter-spacing:.07em;text-transform:uppercase;color:#2463a6;margin-bottom:22px}.brand:before{content:"";width:13px;height:13px;border:3px solid currentColor;border-radius:50%}h1{font-size:clamp(1.45rem,3.3vw,2rem);line-height:1.2;margin:0 0 20px;letter-spacing:-.03em}h2{font-size:1.1rem;margin:26px 0 12px}p,li{line-height:1.65}a{color:#176cb0;text-underline-offset:3px}a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid #60a5fa;outline-offset:3px}.checks{list-style:none;padding:0}.checks li{padding:5px 0}.ok{color:#137d49}.error{color:#b42318}.notice,.success,.attention{padding:16px 18px;border-radius:10px;margin:18px 0;border:1px solid transparent}.notice{background:#fff6e5;border-color:#f4d6a3}.success{background:#ecfdf3;color:#116329;border-color:#bbebcc}.attention{background:#fff1f2;color:#9f1239;border-color:#fecdd3}button{padding:12px 20px;border:0;border-radius:9px;background:#155e9d;color:#fff;font-weight:700;font-size:1rem;cursor:pointer}button:disabled{opacity:.6;cursor:progress}code{background:#eaf0f8;padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}.steps{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0;margin:0 0 25px}.steps li{font-size:.83rem;padding:5px 9px;border-radius:8px;background:#eef3fa;color:#41556d}.steps .current{background:#dbeafe;color:#124e93;font-weight:750}.busy{display:flex;align-items:flex-start;gap:15px;padding:18px;background:#eff7ff;border:1px solid #bfdbfe;border-radius:10px}.busy p{margin:0}.spinner{flex:none;display:inline-block;height:24px;width:24px;border:3px solid #93c5fd;border-top-color:#155e9d;border-radius:50%;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.muted{color:#64748b;font-size:.91rem}.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:20px}@media(prefers-reduced-motion:reduce){.spinner{animation:none;border-style:dotted}}@media(prefers-color-scheme:dark){body{background:#0b1421;color:#e2e8f0}.card{background:#152235;border-color:#304257;box-shadow:none}.brand,a{color:#93c5fd}.checks .ok{color:#6ee7b7}.error{color:#fda4af}.notice{background:#372b1b;border-color:#75532a}.success{background:#13382a;color:#a7f3d0;border-color:#286c49}.attention{background:#3f1d29;color:#fecdd3;border-color:#85384b}code{background:#26384e}.steps li{background:#243348;color:#cbd5e1}.steps .current{background:#234c78;color:#dbeafe}.busy{background:#182e49;border-color:#375c86}.muted{color:#94a3b8}}';
    echo '</style></head><body><main><div class="card"><div class="brand">MCP Gateway / Update</div><h1>'.updaterEscape($title).'</h1>'.$body.'</div></main>';
    if ($script !== null) {
        echo '<script>'.$script.'</script>';
    }
    echo '</body></html>';
    exit;
}

function updaterSteps(string $active): string
{
    $steps = [
        'preflight' => 'Preflight',
        'files' => 'Backup & files',
        'postflight' => 'Database & health',
        'complete' => 'Completion',
    ];
    $result = '<ol class="steps" aria-label="Update phases">';
    foreach ($steps as $key => $label) {
        $current = $key === $active;
        $result .= '<li'.($current ? ' class="current" aria-current="step"' : '').'>'.updaterEscape($label).'</li>';
    }

    return $result.'</ol>';
}

function updaterAutoFinishScript(): string
{
    return <<<'JS'
(() => {
    const form = document.getElementById('continue-update');
    const manual = document.getElementById('manual-continue');
    if (!form || !window.fetch) return;
    if (manual) manual.hidden = true;
    fetch(form.action, {method: 'POST', body: new FormData(form),
        credentials: 'same-origin', cache: 'no-store', redirect: 'error'})
        .then(async response => {
            const html = await response.text();
            document.open();
            document.write(html);
            document.close();
        })
        .catch(() => {
            document.getElementById('progress-message').textContent =
                'The browser connection was interrupted. Completion is not confirmed. Do not start another update.';
            document.getElementById('recovery-link').hidden = false;
        });
})();
JS;
}

function updaterPollScript(): string
{
    return <<<'JS'
(() => {
    const status = document.getElementById('progress-message');
    const fallback = document.getElementById('recovery-link');
    let attempts = 0;
    async function check() {
        try {
            const response = await fetch('/update/', {credentials: 'same-origin',
                cache: 'no-store', redirect: 'error'});
            if (response.status === 202 && ++attempts < 60) {
                setTimeout(check, 8000);
                return;
            }
            if (response.status === 404 || response.status === 410 || attempts >= 60) {
                status.textContent = 'The temporary updater is no longer reporting progress. Check the administrator panel to verify service before taking further action.';
                fallback.hidden = false;
                return;
            }
            const html = await response.text();
            document.open();
            document.write(html);
            document.close();
        } catch (_) {
            status.textContent = 'Progress cannot be verified from this browser. The server may still be working; do not restart the update.';
            fallback.hidden = false;
        }
    }
    setTimeout(check, 8000);
})();
JS;
}

function updaterStartScript(): string
{
    return <<<'JS'
(() => {
    const form = document.getElementById('start-update');
    if (!form) return;
    form.addEventListener('submit', () => {
        const button = form.querySelector('button[type="submit"]');
        if (button) {
            button.disabled = true;
            button.textContent = 'Preparing backup and staging files…';
        }
        const state = document.getElementById('start-progress');
        if (state) state.hidden = false;
    });
})();
JS;
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
            updaterSteps('complete').'<div class="success" role="status"><strong>Update complete.</strong><p>MCP Gateway '.updaterEscape($result['from']).' → '.updaterEscape($result['to']).' is installed and the application is live.</p></div>'.$warning.'<p><a href="/admin">Open administrator panel</a></p>',
        );
    } catch (UpdateBusyException) {
        updaterRender('MCP Gateway Update In Progress',
            updaterSteps('postflight')
            .'<div class="busy" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span><p id="progress-message">Another authorized update step is already running. No second operation was started.</p></div>'
            .'<p id="recovery-link" class="notice" hidden>Unable to verify progress. Check <a href="/admin">the administrator panel</a> without restarting the update.</p>',
            202, updaterPollScript());
    } catch (Throwable $exception) {
        updaterRender(
            'MCP Gateway Update Needs Attention',
            '<p class="error">'.updaterEscape($exception->getMessage()).'</p><div class="notice">Do not re-extract or start another update unless the message above confirms that the previous application files were restored and the application returned to service.</div>',
            500,
        );
    }
}

// During maintenance, never attempt /admin authentication for the browser
// bound to an active update. That request can return a misleading HTTP 403.
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $status = $browserToken !== '' ? $updater->browserUpdateStatus($browserToken) : null;
    if ($status !== null) {
        $phase = $status['phase'];
        if (str_starts_with($phase, 'failed-')) {
            $message = $phase === 'failed-after-migration-start'
                ? 'The previous update reached the database-migration boundary and did not finish safely.'
                : 'The previous update failed before migration and automatic code restoration could not finish safely.';
            updaterRender('MCP Gateway Update Needs Attention',
                updaterSteps('postflight').'<div class="attention" role="alert">'.updaterEscape($message).'</div>'
                .'<p>Do not start another update or roll back database migrations blindly. Maintenance and the private code backup must be assessed by the operator.</p>',
                503);
        }

        if ($phase === 'files-replaced' && $status['continuation'] !== null) {
            updaterRender('Resume MCP Gateway Update',
                updaterSteps('postflight')
                .'<p>Application files are staged. Database migrations and final health checks have <strong>not</strong> started. This browser can safely continue this exact staged update.</p>'
                .'<form id="continue-update" method="post" action="/update/"><input type="hidden" name="action" value="finish"><input type="hidden" name="continuation" value="'.updaterEscape($status['continuation']).'">'
                .'<div class="busy" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span><p id="progress-message">Continuing database and health checks. Keep this page open; no manual refresh is needed.</p></div>'
                .'<div class="actions"><button id="manual-continue" type="submit">Continue update</button></div></form>'
                .'<p class="muted">Without JavaScript, select Continue update once. Do not run a second update package.</p>'
                .'<p id="recovery-link" class="notice" hidden>Connection uncertain. <a href="/update/">Check update status in this browser</a> or <a href="/admin">verify the administrator panel</a>. Do not start again blindly.</p>',
                200, updaterAutoFinishScript());
        }

        if ($status['running']) {
            $filePhase = $phase === 'replace-files';
            updaterRender('MCP Gateway Update In Progress',
                updaterSteps($filePhase ? 'files' : 'postflight')
                .'<div class="busy" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span>'
                .'<p id="progress-message">'.($filePhase
                    ? 'The server is replacing managed files from the verified package.'
                    : 'Database and health checks are running on the server. This can take longer than file replacement.')
                .' Do not submit the update again.</p></div>'
                .'<p class="muted">This page checks for a state change automatically. No percentage or completion time is estimated.</p>'
                .'<p id="recovery-link" class="notice" hidden>Progress cannot be confirmed. Check <a href="/admin">the administrator panel</a>; do not retry migrations or delete recovery state.</p>',
                202, updaterPollScript());
        }

        $explanation = $status['expired']
            ? 'The browser continuation session expired before the final step.'
            : ($phase === 'migrate'
                ? 'The final step started but is no longer running. The database may be partially migrated.'
                : 'The update stopped in a state that cannot be resumed automatically.');
        updaterRender('MCP Gateway Update Needs Attention',
            updaterSteps($phase === 'replace-files' ? 'files' : 'postflight')
            .'<div class="attention" role="alert">'.updaterEscape($explanation).'</div>'
            .'<p>Preserve the private updater state and code backup. Do not restart the update or run migration rollback without verifying recovery state.</p>',
            503);
    }

    if (is_file($basePath.'/storage/app/private/update-state.json')) {
        updaterRender('Update Session Cannot Be Verified',
            '<div class="attention" role="alert">An update or recovery state exists, but this browser is not authorized to resume it.</div>'
            .'<p>Return to the original update browser session. Do not start another update, change cookies or bypass administrator authentication.</p>',
            403);
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

        // The internal request owns the Laravel session cookie. Forward it to
        // the real response so /admin/login can return the operator directly
        // to /update/ instead of requiring the update URL to be opened twice.
        foreach ($authResponse->headers->getCookies() as $cookie) {
            header('Set-Cookie: '.$cookie, false);
        }

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
} catch (Throwable) {
    updaterRender('MCP Gateway Update', '<p class="error">Could not initialize the authenticated update session.</p>', 500);
}

if ($browserToken === '' || ! preg_match('/^[a-f0-9]{64}$/', $browserToken)) {
    $browserToken = bin2hex(random_bytes(32));
    updaterCookie($browserToken);
}

try {
    $info = $updater->inspect();
    $resetPlan = $updater->targetResetPreflight();
} catch (Throwable $exception) {
    updaterRender('MCP Gateway Update', '<p class="error">'.updaterEscape($exception->getMessage()).'</p>', 400);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'start') {
    $postedCsrf = is_string($_POST['_token'] ?? null) ? $_POST['_token'] : '';
    if ($postedCsrf === '' || ! hash_equals($csrf, $postedCsrf)) {
        updaterRender('MCP Gateway Update', '<p class="error">The administrator session expired. Reload this page and try again.</p>', 419);
    }

    try {
        $result = $updater->stage($browserToken, [
            'reset_acknowledged' => is_string($_POST['reset_acknowledged'] ?? null) ? $_POST['reset_acknowledged'] : '',
            'database_backup_verified' => is_string($_POST['database_backup_verified'] ?? null) ? $_POST['database_backup_verified'] : '',
            'confirmed_target_version' => is_string($_POST['confirmed_target_version'] ?? null) ? $_POST['confirmed_target_version'] : '',
            'package_sha256' => is_string($_POST['package_sha256'] ?? null) ? $_POST['package_sha256'] : '',
        ]);
        updaterRender('Finalizing MCP Gateway Update',
            updaterSteps('postflight')
            .'<p>Backup and managed-file replacement completed. Database/cache migrations and health checks are the next server-side step.</p>'
            .'<form id="continue-update" method="post" action="/update/"><input type="hidden" name="action" value="finish"><input type="hidden" name="continuation" value="'.updaterEscape($result['continuation']).'">'
            .'<div class="busy" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span><p id="progress-message">Completing database and health checks. This page will show the result when the server responds; do not refresh or start a second update.</p></div>'
            .'<div class="actions"><button id="manual-continue" type="submit">Continue update</button></div></form>'
            .'<p class="muted">Without JavaScript, select Continue update once to perform the final step.</p>'
            .'<p id="recovery-link" class="notice" hidden>Completion cannot be confirmed. <a href="/update/">Check this update in the same browser</a> or <a href="/admin">verify the administrator panel</a>. Do not retry an uncertain migration.</p>',
            200, updaterAutoFinishScript());
    } catch (UpdateBusyException) {
        updaterRender('Another Update Step Is Running',
            updaterSteps('files').'<div class="notice" role="status">This request did not start a second update. Return to the original browser tab; do not submit again.</div>',
            409);
    } catch (Throwable $exception) {
        updaterRender(
            'MCP Gateway Update Failed',
            '<p class="error">'.updaterEscape($exception->getMessage()).'</p><p>Follow the recovery state reported above before attempting another update.</p>',
            500,
        );
    }
}

$checks = '';
foreach ($info['checks'] as $label => $passed) {
    $checks .= '<li class="'.($passed ? 'ok' : 'error').'">'.($passed ? '✓' : '✗').' '.updaterEscape($label).'</li>';
}

$resetWarning = '';
$resetFields = '';
if ($resetPlan['required']) {
    $affected = '';
    foreach ($resetPlan['affected'] as $label => $present) {
        if ($present) {
            $affected .= '<li>'.updaterEscape($label).'</li>';
        }
    }
    $resetWarning = '<div class="notice" role="alert"><h2>Breaking v2.0 Target/OAuth reset — independent database backup REQUIRED</h2>'
        .'<p>This upgrade permanently removes legacy WordPress Site registrations/credentials, Target assignments and groups, pending Target work, old Target-scoped Activity, and Gateway OAuth grants, access/refresh tokens and pending codes (including ChatGPT). Exact affected categories currently found:</p><ul>'.$affected.'</ul>'
        .'<p>Administrator accounts, roles, encryption/signing keys, global permission denials, configured client profiles, and unrelated Gateway Activity must be preserved. Every WordPress Target and ChatGPT client must reauthorize.</p>'
        .'<p><strong>The updater creates a CODE backup only; it is NOT a database backup.</strong> Before clicking Update, put the Gateway into an operator-controlled safe upgrade window, create a consistent independent database backup, and prove restoration into a separate disposable database. MariaDB partial DDL cannot be safely rolled back by this updater. Keep the backup outside the installation.</p>'
        .'<p>Both confirmations are required for this exact '.updaterEscape($info['installed']).' → '.updaterEscape($info['target']).' update package. Pre-configured .env consent alone is insufficient.</p></div>';
    $resetFields = '<p><label><input type="checkbox" name="reset_acknowledged" value="RESET_TARGET_STATE" required> '
        .'I explicitly approve the permanent reset of the above legacy Target/WordPress and Gateway OAuth connection state for this update.</label></p>'
        .'<p><label><input type="checkbox" name="database_backup_verified" value="RESTORABLE_DATABASE_BACKUP_VERIFIED" required> '
        .'I independently created and verified restoration of a consistent full database backup, stored separately from the updater code backup.</label></p>';
}

updaterRender(
    'Update MCP Gateway',
    updaterSteps('preflight').'<p>This temporary updater will upgrade the current Gateway without SSH, Git, or Composer.</p><p><strong>Installed:</strong> '.updaterEscape($info['installed']).'<br><strong>Target:</strong> '.updaterEscape($info['target']).'</p><h2>Preflight</h2><ul class="checks">'.$checks.'</ul><div class="notice">The existing <code>.env</code> and persistent <code>storage/</code> are preserved. A private code backup is retained before any managed files are replaced.</div>'
    .$resetWarning
    .'<form id="start-update" method="post"><input type="hidden" name="_token" value="'.updaterEscape($csrf).'"><input type="hidden" name="action" value="start">'
    .'<input type="hidden" name="confirmed_target_version" value="'.updaterEscape($resetPlan['to']).'"><input type="hidden" name="package_sha256" value="'.updaterEscape($resetPlan['package_sha256']).'">'
    .$resetFields.'<button type="submit">Update MCP Gateway</button></form>'
    .'<div id="start-progress" class="busy" role="status" aria-live="polite" hidden><span class="spinner" aria-hidden="true"></span><p>Creating the private code backup and replacing managed files. Keep this page open.</p></div>',
    200, updaterStartScript(),
);
