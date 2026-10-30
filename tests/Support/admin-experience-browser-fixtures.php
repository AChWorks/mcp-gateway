<?php

/**
 * Explicitly enabled synthetic UI fixtures, included only by the guarded
 * loopback development router. No production route or remote operation.
 */
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Activity\ActivityRecorder;
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
    Auth::login($user);

    return redirect()->route('admin.dashboard');
});

Route::middleware(['web', 'auth'])->post('/__browser__/experience-expire', static function (Request $request) {
    Auth::logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return response('', 204);
});
