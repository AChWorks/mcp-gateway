<?php

declare(strict_types=1);

use App\Application\Operations\OperationalSettings;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use Illuminate\Console\Events\ScheduledTaskFinished;
use Illuminate\Console\Events\ScheduledTaskStarting;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

/** Observe the actual scheduled command process, not a mocked due-work call. */
function installedOAuthScheduler(string $root): array
{
    $path = tempnam($root.'/secrets', 'maintenance-');
    if ($path === false) {
        throw new RuntimeException('Could not allocate private maintenance output.');
    }
    chmod($path, 0600);
    $matches = [];
    Event::listen(ScheduledTaskStarting::class, static function (ScheduledTaskStarting $event) use ($path): void {
        if (str_contains((string) $event->task->command, 'gateway:wordpress-credentials-maintain')) {
            $event->task->sendOutputTo($path);
        }
    });
    Event::listen(ScheduledTaskFinished::class, static function (ScheduledTaskFinished $event) use (&$matches): void {
        if (str_contains((string) $event->task->command, 'gateway:wordpress-credentials-maintain')) {
            $matches[] = $event->task->exitCode;
        }
    });
    try {
        $status = Artisan::call('schedule:run');
        $output = (string) file_get_contents($path);
        if ($status !== 0 || count($matches) !== 1 || ! is_int($matches[0])
            || ! preg_match('/WordPress Target maintenance: scanned=(\d+) renewed=(\d+) recovered=(\d+) failed=(\d+)/', $output, $m)) {
            throw new RuntimeException('Actual scheduled maintenance execution or summary was not observed.');
        }

        return ['exit_code' => $matches[0], 'scanned' => (int) $m[1], 'renewed' => (int) $m[2],
            'recovered' => (int) $m[3], 'failed' => (int) $m[4]];
    } finally {
        unlink($path);
    }
}

/**
 * Actual issued grant, accelerated fixture-record age, real HTTPS renewal and
 * independently running SDK/scheduler processes. No provider source patch,
 * fake token endpoint, global clock change or operator credential.
 */
function qualifyInstalledWordpressOAuth(string $root, array $state, Closure $save): array
{
    $check = static function (bool $ok, string $message): void {
        if (! $ok) {
            throw new RuntimeException($message);
        }
    };
    $check($state['wp_target'] === 'mixed-wp', 'Unexpected disposable WordPress Target.');
    // The real scheduler spawns a separate artisan process. Its PHP must
    // trust exactly the disposable TLS CA too, without disabling verification.
    $ini = $root.'/secrets/maintenance-ini';
    $check(mkdir($ini, 0700), 'Could not create private fixture PHP configuration.');
    $ca = json_encode($root.'/secrets/tls.crt', JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $check(file_put_contents($ini.'/fixture.ini', "curl.cainfo=$ca\nopenssl.cafile=$ca\n") !== false,
        'Could not configure the disposable scheduler TLS trust.');
    chmod($ini.'/fixture.ini', 0600);
    putenv('PHP_INI_SCAN_DIR='.(getenv('PHP_INI_SCAN_DIR') ?: '').PATH_SEPARATOR.$ini);
    $run = static function (array $command, string $label, ?array $input = null) use ($root): array {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'a']],
            $pipes, $root.'/gateway');
        if (! is_resource($process)) {
            throw new RuntimeException('Could not launch disposable OAuth '.$label.'.');
        }
        if ($input !== null) {
            $encoded = json_encode($input, JSON_THROW_ON_ERROR);
            if (fwrite($pipes[0], $encoded) !== strlen($encoded)) {
                fclose($pipes[0]);
                fclose($pipes[1]);
                proc_close($process);
                throw new RuntimeException('Could not send the private fixture input.');
            }
        }
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $status = proc_close($process);
        if ($status !== 0) {
            throw new RuntimeException('Disposable OAuth '.$label.' failed (exit '.$status.').');
        }
        try {
            $result = json_decode((string) $output, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException('Invalid sanitized OAuth evidence: '.$label.'.');
        }
        if (! is_array($result)) {
            throw new RuntimeException('Missing sanitized OAuth evidence: '.$label.'.');
        }

        return $result;
    };
    $native = static fn (array $secret, string $mode = 'observe', int $seconds = 0): array => $run([
        PHP_BINARY, $root.'/wp-cli.phar', '--path='.$root.'/wp', '--user=mixedadmin',
        'eval-file', $root.'/gateway/tests/Support/installed-mixed/wp-oauth-native.php',
    ], 'provider-'.$mode, [
        'mode' => $mode, 'seconds' => $seconds, 'client_id' => $secret['client_id'],
        'resource_url' => $secret['resource_url'], 'access_token' => $secret['access_token'],
        'refresh_token' => $secret['refresh_token'],
    ]);
    $probe = static fn (string $mode): array => $run([
        'env', 'MIXED_ROOT='.$root, PHP_BINARY, $root.'/client/client.php', 'wp-oauth', $mode,
    ], 'SDK-'.$mode);
    $schedule = static fn (): array => $run([
        PHP_BINARY, $root.'/gateway/tests/Support/installed-mixed/seed.php', 'wp-oauth-schedule',
    ], 'schedule-run');
    $snapshot = static function () use ($state): array {
        $target = Target::query()->where('target_id', $state['wp_target'])->sole();
        $credential = TargetCredential::query()->where('target_record_id', $target->id)
            ->where('purpose', WpAiBridgeTargetVault::PURPOSE)->sole();
        $meta = DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->id)->sole();

        return ['target' => $target, 'credential' => $credential, 'meta' => $meta,
            'secret' => app(WpAiBridgeTargetVault::class)->openCredential($target, $credential),
            'intent' => DB::table('wp_ai_bridge_refresh_intents')->where('target_record_id', $target->id)->first()];
    };
    $identity = static function (array $s): array {
        $scopes = $s['secret']['scopes'];
        sort($scopes);

        return [$s['target']->id, $s['target']->transportAuthorityFingerprint(),
            $s['credential']->authorityFingerprint(), $s['meta']->binding_hash,
            $s['secret']['client_id'], $s['secret']['resource_url'], $scopes];
    };
    $material = static fn (array $s): array => [(int) $s['meta']->generation,
        $s['credential']->materialFingerprint(), $s['meta']->access_expires_at,
        $s['meta']->refresh_expires_at, $s['meta']->refresh_due_at];
    $initial = $snapshot();
    $grant = $identity($initial);
    $check(hash_equals($initial['secret']['access_token'], $state['wp_direct']['access_token'])
        && $initial['secret']['resource_url'] === $state['wp_direct']['resource'], 'Initial direct grant differs.');
    $tolerance = app(OperationalSettings::class)->httpTimeoutsSeconds()['request'] + 2;
    $fresh = static function (array $s) use ($check, $native, $identity, $grant, $tolerance): array {
        $access = $s['secret']['access_expires_at']?->getTimestamp();
        $refresh = strtotime((string) $s['meta']->refresh_expires_at);
        $due = strtotime((string) $s['meta']->refresh_due_at);
        $provider = $native($s['secret']);
        $check($identity($s) === $grant && $s['intent'] === null
            && $s['target']->connection_state === TargetConnectionState::Connected
            && $access === strtotime((string) $s['meta']->access_expires_at)
            && $access > time() && $due > $access
            && $refresh - $due === 1296000 && $refresh - $access === 2592000 - 3600,
            'Fresh installed grant or actual 30-day/one-hour scheduling contract differs.');
        $scopes = $s['secret']['scopes'];
        sort($scopes);
        foreach (['access' => $access, 'refresh' => $refresh] as $kind => $expires) {
            $claims = $provider[$kind] ?? null;
            $observedScopes = $claims['scopes'] ?? [];
            sort($observedScopes);
            $check(is_array($claims) && $claims['principal_id'] === 1 && $observedScopes === $scopes
                && abs($claims['expires_at'] - $expires) <= $tolerance, 'Native stored OAuth claims or lifetime differs.');
        }
        $check($provider['access']['client_revision'] === $provider['refresh']['client_revision'],
            'Native access/refresh client revision differs.');

        return $provider;
    };
    $nativeInitial = $fresh($initial);
    $noDue = ['exit_code' => 0, 'scanned' => 0, 'renewed' => 0, 'recovered' => 0, 'failed' => 0];
    $renewed = ['exit_code' => 0, 'scanned' => 1, 'renewed' => 1, 'recovered' => 0, 'failed' => 0];
    $quiet = static function (array $before) use ($schedule, $snapshot, $material, $check, $noDue): array {
        $result = $schedule();
        $check($result === $noDue && $material($snapshot()) === $material($before),
            'Scheduler rotated a non-due idle grant or did not dispatch.');

        return $result;
    };
    $age = static function (array $before, bool $due) use ($native, $snapshot, $identity, $grant, $check): array {
        $secret = $before['secret'];
        $access = $secret['access_expires_at']->getTimestamp();
        $refresh = strtotime((string) $before['meta']->refresh_expires_at);
        $nextDue = strtotime((string) $before['meta']->refresh_due_at);
        $seconds = ($due ? $nextDue : $access) - time() + 60;
        $check($seconds > 0 && $refresh - $seconds > time(), 'Invalid fixture age selection.');
        $provider = $native($secret, 'age', $seconds);
        $check($provider['access'] === null && $provider['refresh'] !== null, 'Native access expiry or renewable refresh age was not established.');
        DB::transaction(static function () use ($before, $secret, $access, $refresh, $nextDue, $seconds): void {
            $before['credential']->forceFill(['encrypted_payload' => app(WpAiBridgeTargetVault::class)->sealCredential(
                $before['target'], $secret['client_id'], $secret['resource_url'], $secret['access_token'],
                $secret['refresh_token'], new DateTimeImmutable('@'.($access - $seconds)), $secret['scopes'],
            )])->save();
            DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $before['credential']->id)->update([
                'access_expires_at' => now()->setTimestamp($access - $seconds),
                'refresh_expires_at' => now()->setTimestamp($refresh - $seconds),
                'refresh_due_at' => now()->setTimestamp($nextDue - $seconds),
            ]);
            $before['target']->forceFill(['last_tested_at' => now()->subSeconds($seconds),
                'last_success_at' => now()->subSeconds($seconds)])->save();
        });
        $aged = $snapshot();
        $check($identity($aged) === $grant && (int) $aged['meta']->generation === (int) $before['meta']->generation
            && $aged['intent'] === null && $aged['target']->connection_state === TargetConnectionState::Connected
            && $aged['secret']['access_expires_at']->getTimestamp() <= time()
            && (strtotime((string) $aged['meta']->refresh_due_at) <= time()) === $due,
            'Aging changed authorization, generation or due-work state.');

        return [$aged, $seconds];
    };
    $expected = ['ok' => true, 'data' => ['bytes' => strlen('idle-credential-probe'),
        'sha256' => hash('sha256', 'idle-credential-probe'), 'principal_id' => 1]];
    $denyDirect = static function () use ($check, $probe): void {
        $check($probe('direct-denied') === ['http_status' => 401], 'Expired provider access bearer was not rejected by real HTTPS.');
    };
    $rotated = static function (array $before) use ($snapshot, $fresh, $native, $nativeInitial, $check, $probe, $expected, $save, &$state, $material): array {
        $after = $snapshot();
        $provider = $fresh($after);
        $check((int) $after['meta']->generation === (int) $before['meta']->generation + 1
            && ! hash_equals($after['secret']['access_token'], $before['secret']['access_token'])
            && ! hash_equals($after['secret']['refresh_token'], $before['secret']['refresh_token'])
            && $native($before['secret']) === ['access' => null, 'refresh' => null]
            && $provider['refresh']['client_revision'] === $nativeInitial['refresh']['client_revision'],
            'Expected exactly one real provider rotation within the original grant.');
        $state['wp_direct']['access_token'] = $after['secret']['access_token'];
        $save($state);
        $check($probe('direct') === $expected && $probe('routed') === $expected
            && $material($snapshot()) === $material($after),
            'Same-grant post-rotation direct/routed readback or generation differs.');

        return $after;
    };

    $result = ['age_method' => 'exact fixture expiry records; not elapsed real idle time',
        'access_lifetime_seconds' => 3600, 'refresh_lifetime_seconds' => 2592000,
        'idle_maintenance_delay_seconds' => 1296000, 'initial_generation' => (int) $initial['meta']->generation,
        'initial_non_due' => $quiet($initial), 'cycles' => []];
    fwrite(STDERR, "Stage: actual expired access / not-due offline grant\n");
    [$aged, $seconds] = $age($initial, false);
    $denyDirect();
    $nonDue = $quiet($aged);
    $check($probe('routed') === $expected, 'Expired access bearer did not recover through actual Gateway MCP.');
    $current = $rotated($aged);
    $result['cycles'][] = ['kind' => 'on_demand', 'simulated_age_seconds' => $seconds,
        'expired_direct_401' => true, 'non_due_scheduler' => $nonDue,
        'generation' => (int) $current['meta']->generation, 'old_refresh_record_consumed' => true,
        'same_grant_direct_routed_principal' => 1];
    for ($cycle = 1; $cycle <= 2; $cycle++) {
        fwrite(STDERR, 'Stage: actual scheduled idle renewal '.$cycle."\n");
        $quiet($current);
        [$aged, $seconds] = $age($current, true);
        $denyDirect();
        $dispatch = $schedule();
        $check($dispatch === $renewed, 'Actual scheduled idle renewal did not complete exactly once.');
        $current = $rotated($aged);
        $result['cycles'][] = ['kind' => 'scheduled', 'simulated_age_seconds' => $seconds,
            'expired_direct_401' => true, 'scheduler' => $dispatch, 'generation' => (int) $current['meta']->generation,
            'old_refresh_record_consumed' => true, 'same_grant_direct_routed_principal' => 1];
    }
    $result['final_non_due'] = $quiet($current);
    fwrite(STDERR, "Stage: actual revoked provider grant / terminal renewal\n");
    [$aged, $seconds] = $age($current, true);
    $denyDirect();
    $check($native($aged['secret'], 'revoke-refresh') === ['access' => null, 'refresh' => null],
        'Native provider-side refresh revocation was not observed.');
    $failure = $schedule();
    $terminal = $snapshot();
    $check($failure === ['exit_code' => 1, 'scanned' => 1, 'renewed' => 0, 'recovered' => 0, 'failed' => 1]
        && $terminal['target']->connection_state === TargetConnectionState::Error
        && $terminal['target']->last_error_code === 'refresh_rejected'
        && $terminal['intent'] !== null && (int) $terminal['intent']->attempts === 2
        && $material($terminal) === $material($aged) && $identity($terminal) === $grant,
        'Terminal native revocation did not preserve the expected fenced grant outcome.');
    $later = $schedule();
    $denied = $probe('routed');
    $end = $snapshot();
    $check($later === $noDue && $denied === ['ok' => false, 'error_code' => 'refresh_pending']
        && $material($end) === $material($terminal) && $end['intent'] == $terminal['intent']
        && $native($end['secret']) === ['access' => null, 'refresh' => null],
        'Terminal revoked grant was not kept fenced across later scheduled and routed work.');
    $result['terminal_revocation'] = ['simulated_age_seconds' => $seconds, 'provider_refresh_revoked' => true,
        'scheduler' => $failure, 'target_state' => 'error', 'error_code' => 'refresh_rejected',
        'fenced_attempts' => 2, 'later_scheduler' => $later, 'routed_error' => $denied['error_code'],
        'generation_unchanged' => true];

    return $result;
}
