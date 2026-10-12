<?php

declare(strict_types=1);

/**
 * CLI-only, disposable installed-Gateway seed program. Invoked against the
 * installed package with real MariaDB, outbound HTTPS, and OpenSSH. No fakes.
 *
 * $argv[1]: init | complete | disable
 */
use App\Application\Access\UserAccessManager;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Application\Targets\WpAiBridgeTargetRegistration;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpClient;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeMcpException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Infrastructure\OAuth\ClientProfileRegistry;
use App\Infrastructure\OAuth\League\Entities\ClientEntity;
use App\Infrastructure\OAuth\League\Entities\ScopeEntity;
use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\CryptKey;

require dirname(__DIR__, 3).'/vendor/autoload.php';
$app = require dirname(__DIR__, 3).'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$stateFile = (string) getenv('MIXED_STATE_FILE');
if ($stateFile === '' || ! str_starts_with($stateFile, '/')) {
    throw new RuntimeException('MIXED_STATE_FILE must be an absolute disposable fixture path.');
}

$save = static function (array $state) use ($stateFile): void {
    $json = json_encode($state, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);
    if (file_put_contents($stateFile, $json, LOCK_EX) === false) {
        throw new RuntimeException('Cannot write fixture state.');
    }
    chmod($stateFile, 0600);
};
$read = static function () use ($stateFile): array {
    return json_decode((string) file_get_contents($stateFile), true, 512, JSON_THROW_ON_ERROR);
};
$token = static function (int $userId, string $clientId, bool $approve): string {
    $resource = (string) config('oauth.resource');
    if ($approve) {
        app(OAuthAuthorizationStore::class)->approve($userId, $clientId, $resource, ['mcp']);
    }
    $value = app(AccessTokenRepository::class)->getNewToken(
        new ClientEntity($clientId, 'Installed mixed SDK acceptance', ['https://11.22.33.45/fixture/callback']),
        [new ScopeEntity('mcp')],
        (string) $userId,
    );
    $value->setIdentifier(bin2hex(random_bytes(20)));
    $value->setExpiryDateTime((new DateTimeImmutable)->modify('+15 minutes'));
    $value->setPrivateKey(new CryptKey((string) config('oauth.keys.private')));
    app(AccessTokenRepository::class)->persistNewAccessToken($value);

    return $value->toString();
};
$mode = $argv[1] ?? '';
if ($mode === 'init') {
    $registry = app(ClientProfileRegistry::class);
    $registry->register('acceptance');
    $registry->register('ungranted');
    $registry->register('never_granted');

    $owner = app(UserAccessManager::class)->create([
        'name' => 'Installed mixed owner', 'email' => 'mixed-owner@example.invalid',
        'password' => bin2hex(random_bytes(20)),
        'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => true,
    ], []);
    $operator = app(UserAccessManager::class)->create([
        'name' => 'Installed mixed operator', 'email' => 'mixed-operator@example.invalid',
        'password' => bin2hex(random_bytes(20)),
        'role' => 'operator', 'target_scope_mode' => 'selected', 'access_enabled' => true,
    ], []);

    // Exercise the real Owner-configurable DB settings, not just .env defaults.
    $settings = app(OperationalSettings::class);
    $settings->save($owner, [
        'wp_response_kib' => 96,
        'wp_readonly_response_kib' => 512,
        'wp_connect_timeout_seconds' => 3,
        'wp_request_timeout_seconds' => 9,
        'ssh_transfer_max_kib' => 4096,
        'ssh_transfer_max_seconds' => 30,
    ], $settings->state()['version']);

    $wp = app(WpAiBridgeTargetRegistration::class)->register(
        'mixed-wp', 'Disposable real WordPress', 'https://11.22.33.44',
    );
    $sshd = app(SshTargetRegistration::class)->register(
        'mixed-ssh', 'Disposable real OpenSSH', '11.22.33.46', 46231,
        (string) getenv('MIXED_SSH_USER'),
        trim((string) file_get_contents((string) getenv('MIXED_SSH_HOST_PUB'))),
        'password', trim((string) file_get_contents((string) getenv('MIXED_SSH_PASSWORD_FILE'))), null,
    );
    $verified = app(SshTargetConnectionService::class)->test($sshd);
    if ($verified !== '11.22.33.46') {
        throw new RuntimeException('Host-key-pinned SSH failed to verify exact namespace destination.');
    }
    DB::table('user_target_access')->insert([
        'user_id' => $operator->getKey(), 'target_record_id' => $wp->getKey(), 'allowed' => true,
    ]);
    $url = app(WpAiBridgeTargetConnectionService::class)->begin($wp);
    $save([
        'wp_target' => $wp->target_id, 'ssh_target' => $sshd->target_id,
        'owner_id' => $owner->getKey(), 'operator_id' => $operator->getKey(),
        'authorize_url' => $url,
        'gateway_source_version' => trim((string) file_get_contents(base_path('VERSION'))),
    ]);
    echo "Fixture registered: one WordPress and one verified OpenSSH Target; OAuth consent pending.\n";
} elseif ($mode === 'complete') {
    $state = $read();
    $callback = json_decode((string) file_get_contents((string) getenv('MIXED_CALLBACK_FILE')), true, 512, JSON_THROW_ON_ERROR);
    parse_str((string) parse_url((string) $state['authorize_url'], PHP_URL_QUERY), $query);
    if (($query['state'] ?? null) !== ($callback['state'] ?? null)) {
        throw new RuntimeException('Real WordPress callback state mismatch.');
    }
    app(WpAiBridgeTargetConnectionService::class)->completeCallback(
        (string) $callback['state'], (string) $callback['code'], (string) $callback['iss'], null,
    );
    $state['owner_token'] = $token((int) $state['owner_id'], 'https://mixed-sdk.example.test/allowed', true);
    $state['operator_token'] = $token((int) $state['operator_id'], 'https://mixed-sdk.example.test/allowed', true);
    // A once-authorized second profile is disabled after minting: even its
    // previously valid signed bearer must become unusable immediately.
    // The real repository must reject minting for an enabled but never-granted
    // identity. No signed bearer may be fabricated to bypass this boundary.
    try {
        $token((int) $state['owner_id'], 'https://mixed-sdk.example.test/never-granted', false);
        throw new LogicException('Never-granted OAuth client unexpectedly received a bearer.');
    } catch (RuntimeException $exception) {
        if (! str_contains($exception->getMessage(), 'No active OAuth authorization matches')) {
            throw $exception;
        }
        $state['never_granted_mint_denied'] = true;
    }
    $state['disabled_profile_token'] = $token((int) $state['owner_id'], 'https://mixed-sdk.example.test/ungranted', true);
    app(ClientProfileRegistry::class)->disable('ungranted');
    $save($state);
    echo "Real WordPress authorization-code + signed client assertion succeeded; three signed test bearer tokens persisted (redacted).\n";
} elseif ($mode === 'disable') {
    $state = $read();
    DB::table('users')->where('id', $state['owner_id'])->update(['access_enabled' => false]);
    echo "Previously authorized Gateway owner disabled; existing bearer must fail closed.\n";
} elseif ($mode === 'diagnose') {
    $state = $read();
    $target = Target::query()->where('target_id', $state['wp_target'])->firstOrFail();
    try {
        $catalog = app(WpAiBridgeMcpClient::class)
            ->readAbilities($target, bin2hex(random_bytes(16)), 'wp-ai-bridge/bridge-info');
        echo 'Real downstream catalog probe: '.json_encode(['item_count' => count($catalog['items'] ?? [])], JSON_THROW_ON_ERROR)."\n";
    } catch (WpAiBridgeMcpException $exception) {
        fwrite(STDERR, 'Real downstream diagnostic: reason='.$exception->reason
            .' stage='.$exception->getMessage()."\n");
        exit(3);
    }
} elseif ($mode === 'report') {
    $state = $read();
    $summary = [
        'gateway_source_version' => $state['gateway_source_version'],
        'wp_target' => $state['wp_target'], 'ssh_target' => $state['ssh_target'],
        'targets' => DB::table('targets')->select('target_id', 'connector_type', 'connection_state')->get()->toArray(),
        'migrations_count' => DB::table('migrations')->count(),
        'oauth_client_profiles_count' => DB::table('oauth_client_profiles')->count(),
        'owner_operational_settings' => app(OperationalSettings::class)->state(),
        'effective_http_timeouts_seconds' => app(OperationalSettings::class)->httpTimeoutsSeconds(),
        'effective_ssh_transfer_limits' => app(OperationalSettings::class)->sshTransferLimits(),
        'effective_response_limit_bytes' => app(OperationalSettings::class)->responseLimitBytes(false),
        'effective_readonly_response_limit_bytes' => app(OperationalSettings::class)->responseLimitBytes(true),
        'absolute_http_response_bound_bytes' => SafeHttpClient::ABSOLUTE_MAX_RESPONSE_BYTES,
    ];
    echo json_encode($summary, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)."\n";
} else {
    throw new RuntimeException('Unsupported seed operation.');
}
