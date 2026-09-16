<?php

declare(strict_types=1);

use App\Support\SimpleWebInstaller;

$basePath = dirname(__DIR__);
$autoloadPath = $basePath.'/vendor/autoload.php';

if (! is_file($autoloadPath)) {
    http_response_code(503);
    echo '<!doctype html><meta charset="utf-8"><title>MCP Gateway Installer</title><h1>MCP Gateway Installer</h1><p>The deployment package is incomplete: <code>vendor/autoload.php</code> is missing. Download the deployment-ready ZIP from the GitHub Release instead of the source archive.</p>';
    exit;
}

require $autoloadPath;

if (SimpleWebInstaller::isInstalled($basePath)) {
    header('Location: /admin/login', true, 302);
    exit;
}

$https = SimpleWebInstaller::requestIsHttps($_SERVER);
$checks = SimpleWebInstaller::preflight($basePath, $https);
$preflightPassed = ! in_array(false, $checks, true);
$errors = [];
$success = false;

$nonceCookie = 'mcp_gateway_installer_nonce';
$nonce = (string) ($_COOKIE[$nonceCookie] ?? '');
if (! preg_match('/^[a-f0-9]{64}$/', $nonce)) {
    $nonce = bin2hex(random_bytes(32));
    setcookie($nonceCookie, $nonce, [
        'expires' => time() + 1800,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

$values = [
    'app_url' => SimpleWebInstaller::defaultAppUrl($_SERVER),
    'db_host' => '127.0.0.1',
    'db_port' => '3306',
    'db_database' => '',
    'db_username' => '',
    'admin_name' => '',
    'admin_email' => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    foreach (array_keys($values) as $field) {
        if (isset($_POST[$field]) && is_string($_POST[$field])) {
            $values[$field] = trim($_POST[$field]);
        }
    }

    if (! $preflightPassed) {
        $errors['installer'] = 'Fix the failed server checks before installing.';
    } elseif (! isset($_POST['_installer_nonce']) || ! is_string($_POST['_installer_nonce']) || ! hash_equals($nonce, $_POST['_installer_nonce'])) {
        $errors['installer'] = 'Installer session expired. Reload this page and try again.';
    } else {
        $input = [
            ...$values,
            'db_password' => is_string($_POST['db_password'] ?? null) ? $_POST['db_password'] : '',
            'admin_password' => is_string($_POST['admin_password'] ?? null) ? $_POST['admin_password'] : '',
            'admin_password_confirmation' => is_string($_POST['admin_password_confirmation'] ?? null) ? $_POST['admin_password_confirmation'] : '',
        ];

        $errors = SimpleWebInstaller::validateInput($input, (string) ($_SERVER['HTTP_HOST'] ?? ''));

        if ($errors === []) {
            try {
                SimpleWebInstaller::install($basePath, $input);
                $success = true;
                setcookie($nonceCookie, '', [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Strict',
                ]);
            } catch (Throwable $exception) {
                $errors['installer'] = $exception->getMessage();
            }
        }
    }
}

function installerEscape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MCP Gateway Installer</title>
    <style>
        :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
        body { margin: 0; background: #f4f5f7; color: #1f2937; }
        main { max-width: 760px; margin: 40px auto; padding: 0 20px 48px; }
        .card { background: #fff; border: 1px solid #d9dde3; border-radius: 12px; padding: 24px; box-shadow: 0 8px 24px rgba(0,0,0,.05); }
        h1 { margin-top: 0; }
        h2 { margin: 26px 0 12px; font-size: 1.05rem; }
        label { display: block; margin-top: 14px; font-weight: 600; }
        input { box-sizing: border-box; width: 100%; margin-top: 6px; padding: 10px 12px; border: 1px solid #c8ced8; border-radius: 8px; background: #fff; color: #111827; }
        button { margin-top: 22px; padding: 11px 18px; border: 0; border-radius: 8px; background: #111827; color: #fff; font-weight: 700; cursor: pointer; }
        button[disabled] { opacity: .5; cursor: not-allowed; }
        .checks { list-style: none; padding: 0; margin: 0; }
        .checks li { padding: 4px 0; }
        .ok { color: #087f23; }
        .fail, .error { color: #b42318; }
        .notice { padding: 12px 14px; border-radius: 8px; background: #fff6e5; margin: 14px 0; }
        .success { padding: 16px; border-radius: 8px; background: #e9f8ee; color: #116329; }
        .error { margin-top: 6px; font-size: .92rem; }
        code { background: #eef0f3; padding: 2px 5px; border-radius: 4px; }
        p { line-height: 1.55; }
        @media (prefers-color-scheme: dark) {
            body { background: #111827; color: #e5e7eb; }
            .card { background: #1f2937; border-color: #374151; }
            input { background: #111827; color: #f9fafb; border-color: #4b5563; }
            code { background: #374151; }
            .notice { background: #3b2f16; }
            .success { background: #12351f; color: #9be4ae; }
        }
    </style>
</head>
<body>
<main>
    <div class="card">
        <h1>MCP Gateway Installer</h1>
        <p>Use this once on a fresh deployment package. The installer creates the production environment, database schema, signing keys, and first administrator.</p>

        <?php if ($success) { ?>
            <div class="success">
                <strong>Installation complete.</strong>
                <p>MCP Gateway is installed and the installer is now locked. Continue to the administrator panel.</p>
                <p><a href="/admin/login">Open administrator login</a></p>
            </div>
        <?php } else { ?>
            <h2>Server checks</h2>
            <ul class="checks">
                <?php foreach ($checks as $label => $passed) { ?>
                    <li class="<?= $passed ? 'ok' : 'fail' ?>"><?= $passed ? '✓' : '✗' ?> <?= installerEscape($label) ?></li>
                <?php } ?>
            </ul>

            <?php if (! $https) { ?>
                <div class="notice">Enable HTTPS for this subdomain before entering database or administrator credentials.</div>
            <?php } ?>

            <?php if (isset($errors['installer'])) { ?>
                <p class="error"><?= installerEscape($errors['installer']) ?></p>
            <?php } ?>

            <form method="post" autocomplete="off">
                <input type="hidden" name="_installer_nonce" value="<?= installerEscape($nonce) ?>">

                <h2>Gateway</h2>
                <label>Application URL
                    <input name="app_url" type="url" required value="<?= installerEscape($values['app_url']) ?>" placeholder="https://gateway.example.com">
                </label>
                <?php if (isset($errors['app_url'])) { ?><div class="error"><?= installerEscape($errors['app_url']) ?></div><?php } ?>

                <h2>MySQL</h2>
                <label>Host
                    <input name="db_host" required value="<?= installerEscape($values['db_host']) ?>">
                </label>
                <?php if (isset($errors['db_host'])) { ?><div class="error"><?= installerEscape($errors['db_host']) ?></div><?php } ?>

                <label>Port
                    <input name="db_port" inputmode="numeric" required value="<?= installerEscape($values['db_port']) ?>">
                </label>
                <?php if (isset($errors['db_port'])) { ?><div class="error"><?= installerEscape($errors['db_port']) ?></div><?php } ?>

                <label>Database
                    <input name="db_database" required value="<?= installerEscape($values['db_database']) ?>">
                </label>
                <?php if (isset($errors['db_database'])) { ?><div class="error"><?= installerEscape($errors['db_database']) ?></div><?php } ?>

                <label>Username
                    <input name="db_username" required value="<?= installerEscape($values['db_username']) ?>">
                </label>
                <?php if (isset($errors['db_username'])) { ?><div class="error"><?= installerEscape($errors['db_username']) ?></div><?php } ?>

                <label>Password
                    <input name="db_password" type="password" required autocomplete="new-password">
                </label>
                <?php if (isset($errors['db_password'])) { ?><div class="error"><?= installerEscape($errors['db_password']) ?></div><?php } ?>

                <h2>Administrator</h2>
                <label>Name
                    <input name="admin_name" required value="<?= installerEscape($values['admin_name']) ?>">
                </label>
                <?php if (isset($errors['admin_name'])) { ?><div class="error"><?= installerEscape($errors['admin_name']) ?></div><?php } ?>

                <label>Email
                    <input name="admin_email" type="email" required value="<?= installerEscape($values['admin_email']) ?>">
                </label>
                <?php if (isset($errors['admin_email'])) { ?><div class="error"><?= installerEscape($errors['admin_email']) ?></div><?php } ?>

                <label>Password
                    <input name="admin_password" type="password" required autocomplete="new-password">
                </label>
                <?php if (isset($errors['admin_password'])) { ?><div class="error"><?= installerEscape($errors['admin_password']) ?></div><?php } ?>

                <label>Confirm password
                    <input name="admin_password_confirmation" type="password" required autocomplete="new-password">
                </label>
                <?php if (isset($errors['admin_password_confirmation'])) { ?><div class="error"><?= installerEscape($errors['admin_password_confirmation']) ?></div><?php } ?>

                <button type="submit" <?= $preflightPassed ? '' : 'disabled' ?>>Install MCP Gateway</button>
            </form>

            <p><small>The selected MySQL database must be dedicated and empty. Secrets are written only to the private <code>.env</code> / key files and are never displayed by this page.</small></p>
        <?php } ?>
    </div>
</main>
</body>
</html>
