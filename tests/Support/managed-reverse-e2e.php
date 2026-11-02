<?php

/**
 * Disposable GitHub Actions acceptance harness (not a production endpoint).
 * Owns one SQLite DB, one independently pinned Target sshd, one controlled
 * host manifest and one exact generated single-command onboarding operation.
 */
declare(strict_types=1);

use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseInstallCommand;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use Illuminate\Contracts\Console\Kernel;

require dirname(__DIR__, 2).'/vendor/autoload.php';
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$mode = $argv[1] ?? '';
$root = getenv('MANAGED_REVERSE_E2E_DIR');
if (getenv('GITHUB_ACTIONS') !== 'true' || $root === false || ! is_dir($root)) {
    throw new RuntimeException('Only the isolated GitHub Actions acceptance fixture may run.');
}

$targetId = 'ci-managed-reverse';
$targetPort = (int) getenv('MANAGED_REVERSE_TARGET_PORT');
$controlPort = (int) getenv('MANAGED_REVERSE_CONTROL_PORT');
// The root-owned manifest deliberately exposes the verified PUBLIC control
// host identity; the root-only SSHD key files are never opened by Laravel.
$manifest = json_decode(
    (string) file_get_contents('/etc/mcp-gateway-reverse/manifest.json'),
    true, 16, JSON_THROW_ON_ERROR,
);
$controlPin = (string) $manifest['control_host_key'];

if ($mode === 'enroll') {
    $pin = trim((string) file_get_contents($root.'/target-host.pub'));
    $pin = implode(' ', array_slice(preg_split('/\s+/', $pin), 0, 2));
    SshManagedReverseGateway::query()->create([
        'id' => 1,
        'enabled' => true,
        'control_host' => '127.0.0.1',
        'control_port' => $controlPort,
        'control_user' => 'mcp-reverse',
        'control_host_key' => $controlPin,
    ]);

    $result = app(SshManagedReverseEnrollmentService::class)->begin(
        $targetId, 'Disposable E2E Target',
        '8.8.8.8', $targetPort, 'mcptargetci', $pin,
    );
    $enrollment = $result['enrollment'];
    $command = app(SshManagedReverseInstallCommand::class)
        ->command($enrollment, $result['token']);
    file_put_contents($root.'/one-command.sh', $command."\n", LOCK_EX);
    file_put_contents($root.'/enrollment-id', (string) $enrollment->id, LOCK_EX);
    echo "One-use Target command generated from application state (not logged).\n";
    exit(0);
}

$target = Target::query()->where('target_id', $targetId)->firstOrFail();
$config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
$credential = TargetCredential::query()->where('target_record_id', $target->getKey())->firstOrFail();
$vault = app(SshTargetVault::class);
$material = $vault->open($target, $config, $credential);
$policy = app(SshReverseRoutePolicy::class);
$route = $policy->forTarget($target, $config);
if (! $route) {
    throw new RuntimeException('Expected approved, Target-bound reverse route.');
}
$transport = app(SshVerifiedTransport::class);
$pin = SshHostKeyPin::fromLine($config->pinned_host_key);

if ($mode === 'verify') {
    $observed = app(SshTargetConnectionService::class)->test($target);
    if (! is_string($observed) || $target->fresh()->connection_state->value !== 'connected') {
        throw new RuntimeException('Real pinned Target SSH login was not recorded as connected.');
    }
    $output = $transport->withAuthenticatedSession(
        $config->endpoint(), $pin, $config->auth_method,
        $material['secret'], $material['passphrase'],
        static fn ($ssh): string => (string) $ssh->exec("printf 'managed-reverse-command-ok'"),
        $route,
    );
    if ($output !== 'managed-reverse-command-ok') {
        throw new RuntimeException('Real SSH command failed across managed reverse route.');
    }
    $content = $transport->withAuthenticatedSftpSession(
        $config->endpoint(), $pin, $config->auth_method,
        $material['secret'], $material['passphrase'],
        static function ($sftp): string {
            $path = '/home/mcptargetci/.mcp-reverse-e2e.txt';
            if (! $sftp->put($path, 'bounded-mcp-reverse-e2e')) {
                throw new RuntimeException('SFTP upload failed.');
            }
            $data = $sftp->get($path);
            $sftp->delete($path);

            return (string) $data;
        },
        null, $route,
    );
    if ($content !== 'bounded-mcp-reverse-e2e') {
        throw new RuntimeException('SFTP roundtrip failed across managed reverse route.');
    }
    // Wrong end-host pin must stop *before* login credentials are disclosed.
    $wrongKey = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr(73), 32));
    try {
        $transport->authenticate(
            $config->endpoint(), SshHostKeyPin::fromLine($wrongKey),
            $config->auth_method, $material['secret'], $material['passphrase'], $route,
        );
        throw new RuntimeException('Mismatched Target SSHD pin unexpectedly authenticated.');
    } catch (SshTargetConnectionException $e) {
        if ($e->reason !== 'host_key_mismatch') {
            throw $e;
        }
    }
    echo "PASS: real Gateway PHP verify, end-host pin, command and SFTP through the installed Target systemd tunnel.\n";
    exit(0);
}

if ($mode === 'offline') {
    try {
        $transport->authenticate(
            $config->endpoint(), $pin, $config->auth_method,
            $material['secret'], $material['passphrase'], $route,
        );
        throw new RuntimeException('Disconnected tunnel silently provided a route.');
    } catch (SshTargetConnectionException $e) {
        if ($e->reason !== 'reverse_listener_unavailable') {
            throw $e;
        }
    }
    echo "PASS: stopped tunnel cannot fall back to the direct Target endpoint.\n";
    exit(0);
}

if ($mode === 'revoke') {
    app(SshManagedReverseEnrollmentService::class)->revoke(
        SshManagedReverseEnrollment::query()->where('target_id', $targetId)->sole(),
    );
    try {
        $policy->forTarget($target, $config);
        throw new RuntimeException('Revoked route was still approved.');
    } catch (SshTargetConnectionException $e) {
        if ($e->reason !== 'reverse_route_not_approved') {
            throw $e;
        }
    }
    echo "PASS: revoked route blocks new Gateway operations.\n";
    exit(0);
}
throw new InvalidArgumentException('Unknown fixture mode.');
