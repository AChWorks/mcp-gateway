<?php

/**
 * Explicitly enabled synthetic UI fixtures, included only by the guarded
 * loopback development router. No production route or remote operation.
 */
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostReadiness;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use phpseclib4\Crypt\EC;

if (! app()->environment('local') || getenv('GATEWAY_BROWSER_FIXTURE') !== '1'
    || getenv('GATEWAY_ADMIN_EXPERIENCE_FIXTURE') !== '1'
    || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    throw new RuntimeException('The Admin experience fixture requires an explicit isolated loopback environment.');
}

// Render real SSH file forms only in this already guarded disposable fixture.
// Browser tests intercept transfer actions before any application execution.
config()->set('ssh.file_transfer.enabled', true);

// The isolated loopback-only browser fixture must exercise the real enabled
// Owner UI without fabricating privileged root files or changing host state.
// Production never binds this synthetic readiness implementation.
app()->instance(ConnectionRelayHostReadiness::class, new class extends ConnectionRelayHostReadiness
{
    public function ready(ConnectionRelay $relay): bool
    {
        // Keep one independently "ready" UI fixture while exposing a real
        // fail-closed degraded and an unverified draft presentation.
        return $relay->relay_id === 'ui-iran';
    }
});

Route::middleware('web')->get('/__browser__/experience/{role}', static function (string $role) {
    abort_unless(in_array($role, ['owner', 'administrator', 'operator', 'viewer'], true), 404);
    $user = User::query()->firstOrCreate(['email' => 'ui-'.$role.'@example.test'], [
        'name' => 'UI Fixture '.ucfirst($role),
        'password' => 'isolated-browser-password',
        'role' => $role,
        'target_scope_mode' => $role === 'viewer' ? 'selected' : 'all',
        'access_enabled' => true,
    ]);

    if (! Target::query()->where('target_id', 'ui-wp-connected')->exists()) {
        $connected = Target::query()->create([
            'target_id' => 'ui-wp-connected', 'display_name' => 'UI Editorial WordPress',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => TargetConnectionState::Connected,
        ]);
        // Synthetic local metadata uses its own endpoint identity. It does not
        // discover/authenticate a provider or reuse the OAuth-race Target.
        $origin = 'https://ui-provider.browser.test';
        WpAiBridgeTargetConfig::query()->create([
            'target_record_id' => $connected->getKey(), 'base_url' => $origin,
            'base_url_hash' => hash('sha256', $origin),
            'mcp_resource_url' => $origin.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $origin,
            'oauth_authorization_url' => $origin.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $origin.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $origin.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
        ]);
        foreach ([
            ['ui-wp-pending', 'UI pending authorization', TargetConnectionState::Pending],
            ['ui-wp-disconnected', 'UI unconnected service', TargetConnectionState::Disconnected],
            ['ui-wp-reconnect', 'UI WordPress reconnect', TargetConnectionState::ReconnectRequired],
            ['ui-wp-reassigning', 'UI WordPress reassigning', TargetConnectionState::Reassigning],
        ] as [$id, $name, $state]) {
            Target::query()->create([
                'target_id' => $id, 'display_name' => $name,
                'connector_type' => 'wp_ai_bridge', 'connection_state' => $state,
            ]);
        }
        $key = implode(' ', array_slice(preg_split('/\s+/', trim(EC::createKey('Ed25519')->getPublicKey()->toString('OpenSSH'))), 0, 2));
        $ssh = app(SshTargetRegistration::class)->register(
            'ui-ssh-connected', 'UI SSH build host', '1.1.1.1', 22,
            'fixture', $key, 'password', 'synthetic-ssh-password', null,
        );
        $ssh->forceFill([
            'connection_state' => TargetConnectionState::Connected,
            'operations_paused' => true, 'last_tested_at' => now(),
        ])->save();
        for ($index = 1; $index <= 7; $index++) {
            Target::query()->create([
                'target_id' => 'ui-error-'.$index,
                'display_name' => 'UI check failure '.$index.' '.str_repeat('long-name-', 6),
                'connector_type' => 'ssh_direct',
                'connection_state' => TargetConnectionState::Error,
                'last_failure_at' => now(),
                'last_failure_code' => 'fixture_check_failed',
            ]);
        }
        app(ActivityRecorder::class)->record(
            (string) Str::uuid(), 'fixture-uncertain-operation', 'unknown', $connected,
            'fixture_unknown', ['failure_origin' => 'connector_protocol', 'provider_error_message' => 'Synthetic result is unknown.'],
        );
    }

    if ($role === 'viewer') {
        $target = Target::query()->where('target_id', 'ui-wp-connected')->sole();
        DB::table('user_target_access')->updateOrInsert([
            'user_id' => $user->getKey(), 'target_record_id' => $target->getKey(),
        ], ['allowed' => true]);
    }
    // Browser-only synthetic route. No SSH client, network or root attestation
    // is created; readiness above is only a screen-rendering fixture.
    foreach ([
        ['ui-iran', 'Iran intermediary — synthetic browser fixture', '198.51.100.42', 46081],
        ['ui-iran-stale', 'Unverified enabled intermediary', '198.51.100.44', 46083],
    ] as [$relayId, $name, $host, $socksPort]) {
        if (ConnectionRelay::query()->where('relay_id', $relayId)->exists()) {
            continue;
        }
        $key = implode(' ', array_slice(preg_split('/\s+/', trim(EC::createKey('Ed25519')->getPublicKey()->toString('OpenSSH'))), 0, 2));
        $relay = ConnectionRelay::query()->create([
            'relay_id' => $relayId, 'display_name' => $name,
            'control_host' => $host, 'control_port' => 22,
            'control_user' => 'ui-only-relay', 'control_host_key' => $key,
            'local_socks_port' => $socksPort,
        ]);
        DB::table('connection_relays')->where('id', $relay->getKey())->update(['enabled' => true]);
    }
    Auth::login($user);

    return redirect()->route('admin.dashboard');
});

// A disabled saved Relay must remain selected and explicitly blocked on Edit,
// not silently present Direct. This disposable fixture creates no connection.
Route::middleware(['web', 'auth'])->get('/__browser__/relay-unavailable-target', static function () {
    abort_unless(Auth::user()?->getRawOriginal('role') === 'owner', 403);
    $relay = ConnectionRelay::query()->where('relay_id', 'ui-iran-offline')->first();
    if (! $relay instanceof ConnectionRelay) {
        $key = implode(' ', array_slice(
            preg_split('/\\s+/', trim(EC::createKey('Ed25519')->getPublicKey()->toString('OpenSSH'))), 0, 2,
        ));
        $relay = ConnectionRelay::query()->create([
            'relay_id' => 'ui-iran-offline', 'display_name' => 'Unusable saved intermediary',
            'control_host' => '198.51.100.43', 'control_port' => 22,
            'control_user' => 'offline-ui-only', 'control_host_key' => $key,
            'local_socks_port' => 46082,
        ]);
    }
    $target = Target::query()->where('target_id', 'ui-relay-unavailable')->first();
    if (! $target instanceof Target) {
        $target = Target::query()->create([
            'target_id' => 'ui-relay-unavailable',
            'display_name' => 'Synthetic disabled route',
            'connector_type' => 'ssh_direct',
            'connection_state' => TargetConnectionState::Disconnected,
        ]);
        DB::table('targets')->where('id', $target->getKey())->update([
            'relay_record_id' => $relay->getKey(), 'relay_binding_revision' => 1,
        ]);
        SshTargetConfig::query()->create([
            'target_record_id' => $target->getKey(),
            'host' => '203.0.113.5', 'port' => 22, 'username' => 'fixture',
            'auth_method' => 'password', 'pinned_host_key' => $relay->control_host_key,
            'route_mode' => 'direct', 'binding_revision' => 0,
        ]);
    }

    return redirect()->route('admin.targets.edit', ['target' => 'ui-relay-unavailable']);
});

// Seed the two real Owner-only revocation pages on this disposable browser DB.
// The tests use actual Admin Blade forms and POST/redirect actions, not a
// synthetic duplicate password field or a production account.
Route::middleware(['web', 'auth'])->get('/__browser__/owner-revocation-forms', static function () {
    $owner = Auth::user();
    abort_unless($owner instanceof User && $owner->getRawOriginal('role') === 'owner', 403);
    $grantId = '01JABBBBBBBBBBBBBBBBBBBBBB';
    DB::table('oauth_authorizations')->updateOrInsert(['id' => $grantId], [
        'user_id' => $owner->getKey(),
        'client_id' => 'ui-revocation-only-client',
        'client_profile_key' => 'chatgpt',
        'client_profile_generation' => 1,
        'resource' => 'https://ui-provider.browser.test/resource',
        'resource_hash' => hash('sha256', 'https://ui-provider.browser.test/resource'),
        'scopes' => json_encode(['mcp:read'], JSON_THROW_ON_ERROR),
        'revoked_at' => null,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $publisher = User::query()->firstOrCreate(['email' => 'ui-publisher@example.test'], [
        'name' => 'UI Browser Publisher',
        'password' => 'isolated-browser-publisher-password',
        'role' => 'operator',
        'target_scope_mode' => 'selected',
        'access_enabled' => true,
    ]);
    $group = TargetGroup::query()->firstOrCreate(['name' => 'UI browser publication group']);
    DB::table('wordpress_publish_group_grants')->updateOrInsert([
        'user_id' => $publisher->getKey(),
        'target_group_id' => $group->getKey(),
    ], ['created_at' => now(), 'updated_at' => now()]);

    return response()->json([
        'oauth' => route('admin.oauth-clients.index'),
        'publishing' => route('admin.users.publishing.index', ['user' => $publisher->getKey()]),
    ]);
});

Route::middleware(['web', 'auth'])->post('/__browser__/experience-expire', static function (Request $request) {
    Auth::logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return response('', 204);
});

// Isolated fixture-only managed Pending Target for real responsive Owner UI
// acceptance. Never creates a real enrollment token or contacts any host.
Route::middleware(['web', 'auth'])->get('/__browser__/managed-reverse-pending', static function () {
    $owner = Auth::user();
    abort_unless($owner instanceof User && $owner->getRawOriginal('role') === 'owner', 403);
    $id = 'ui-managed-pending';
    if (! Target::query()->where('target_id', $id)->exists()) {
        $target = Target::query()->create([
            'target_id' => $id,
            'display_name' => 'UI managed Reverse SSH pending',
            'connector_type' => 'ssh_direct',
            'connection_state' => TargetConnectionState::Pending,
        ]);
        $pin = implode(' ', array_slice(
            preg_split('/\s+/', trim(EC::createKey('Ed25519')->getPublicKey()->toString('OpenSSH'))), 0, 2,
        ));
        SshTargetConfig::query()->create([
            'target_record_id' => $target->getKey(),
            'host' => '8.8.8.8', 'port' => 2222, 'username' => 'deploy.prod',
            'auth_method' => 'private_key', 'pinned_host_key' => $pin,
            'route_mode' => 'reverse', 'reverse_listener_port' => 43123,
            'reverse_tunnel_identity' => 'managed-ui-only',
            'binding_revision' => 0,
        ]);
        SshManagedReverseEnrollment::query()->create([
            'target_id' => $id, 'target_record_id' => $target->getKey(),
            'listener_port' => 43123, 'tunnel_identity' => 'managed-ui-only',
            'login_public_key' => $pin,
            'state' => 'pending', 'publication_pending' => false,
        ]);
    }

    return redirect()->route('admin.targets.show', ['target' => $id]);
});
