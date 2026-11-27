<?php

declare(strict_types=1);

use App\Application\Targets\ConnectionRelayAdministration;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\TargetTransportBinding;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayOnboarding;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use Illuminate\Support\Facades\DB;

/** CLI-only seed against the owned installed fixture, using real application services. */
function installedRelaySeed(string $root, string $mode, array $state, Closure $save): array
{
    $check = static function (bool $condition, string $message): void {
        if (! $condition) {
            throw new RuntimeException($message);
        }
    };
    $check($state['wp_target'] === 'mixed-wp' && $state['ssh_target'] === 'mixed-ssh',
        'Unexpected disposable Target identity.');
    $account = (string) getenv('MIXED_SSH_USER');
    $check(preg_match('/^mcpac[0-9]+$/D', $account) === 1, 'Expected the disposable SSH account.');
    $relayId = 'mixed-native-relay';
    $relayTargetId = 'mixed-relay-ssh';
    if ($mode === 'prepare') {
        $relay = ConnectionRelay::query()->create([
            'relay_id' => $relayId, 'display_name' => 'Disposable native Relay',
            'control_host' => '11.22.33.47', 'control_port' => 46257,
            'control_user' => $account,
            'control_host_key' => trim((string) file_get_contents($root.'/secrets/relay-host.pin')),
            'local_socks_port' => 47531,
        ]);
        $onboarding = app(ConnectionRelayOnboarding::class);
        $onboarding->prepare($relay);
        $relay->refresh();
        foreach (['relay-client.key' => rtrim($onboarding->privateKey($relay))."\n",
            'relay-client.pub' => $relay->login_public_key."\n",
            'relay-known-hosts' => '[11.22.33.47]:46257 '.$relay->control_host_key."\n"] as $file => $contents) {
            $check(is_string($contents) && file_put_contents($root.'/secrets/'.$file, $contents, LOCK_EX) !== false,
                'Could not prepare private disposable Relay identity.');
            chmod($root.'/secrets/'.$file, 0600);
        }

        return ['prepared' => true];
    }
    $relay = ConnectionRelay::query()->where('relay_id', $relayId)->sole();
    $wp = Target::query()->where('target_id', $state['wp_target'])->sole();
    $directSsh = Target::query()->where('target_id', $state['ssh_target'])->sole();
    $check($directSsh->transportKind() === 'direct', 'Direct SSH control must remain independent.');
    $bindings = app(TargetTransportBinding::class);
    $administration = app(ConnectionRelayAdministration::class);
    if ($mode === 'bind') {
        $check($wp->transportKind() === 'direct' && ! $relay->enabled, 'Unexpected initial Relay binding.');
        $administration->setEnabled($relay, $relay->lifecycle_revision, true);
        $relay->refresh();
        $ssh = app(SshTargetRegistration::class)->register(
            $relayTargetId, 'Disposable Relay SSH Target', '11.22.33.46', 46231, $account,
            trim((string) file_get_contents($root.'/secrets/ssh_host.pin')),
            'password', trim((string) file_get_contents($root.'/secrets/ssh-password')), null,
            connectionRelayId: $relayId,
        );
        $check($ssh->relay_record_id === $relay->id
            && app(SshTargetConnectionService::class)->test($ssh) === '',
            'Registered Relay SSH Target did not authenticate through its selected route.');
        $check($bindings->change($wp, $bindings->revision($wp), $relayId), 'WordPress route was not changed.');
        $wp->refresh();
        $check($wp->relay_record_id === $relay->id, 'WordPress was not bound to the actual Relay.');
        // The direct acceptance has already completed. Revoke its exact grant
        // through the selected Relay, then obtain fresh real user consent.
        $connections = app(WpAiBridgeTargetConnectionService::class);
        $check($connections->disconnect($wp), 'Original disposable grant was not revoked.');
        $wp->refresh();
        $check($wp->connection_state === TargetConnectionState::Disconnected
            && ! TargetCredential::query()->where('target_record_id', $wp->id)->exists(),
            'Prior WordPress credential was not removed after confirmed revocation.');
        $state['authorize_url'] = $connections->begin($wp);
        $state['relay_ssh_target'] = $relayTargetId;
        $save($state);

        return ['registered_relay_ssh' => true, 'wp_reconnect_started' => true];
    }

    $ssh = Target::query()->where('target_id', $relayTargetId)->sole();
    $check($relay->enabled && $wp->relay_record_id === $relay->id && $ssh->relay_record_id === $relay->id,
        'Exact persisted shared Relay route differs.');
    $credential = TargetCredential::query()->where('target_record_id', $wp->id)
        ->where('purpose', WpAiBridgeTargetVault::PURPOSE)->sole();
    $secret = app(WpAiBridgeTargetVault::class)->openCredential($wp, $credential);
    $check($wp->connection_state === TargetConnectionState::Connected
        && $secret['resource_url'] === $state['wp_direct']['resource']
        && hash_equals($secret['access_token'], $state['wp_direct']['access_token']),
        'Actual enrolled WordPress grant differs.');
    $generation = (int) DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->id)->value('generation');
    $check($generation === 1, 'Unexpected WordPress refresh during Relay qualification.');
    if ($mode === 'verify') {
        $check(app(SshTargetConnectionService::class)->test($ssh) === '',
            'Selected Relay SSH connection did not verify.');

        return ['shared_bound_targets' => 2, 'verified_ssh' => true,
            'direct_ssh_control' => true, 'wp_generation' => $generation];
    }
    if ($mode === 'restore') {
        // Explicit detach, not automatic fallback. The next independent OAuth
        // lifecycle test must see the still-current grant via its Direct path.
        $check($bindings->change($wp, $bindings->revision($wp), null)
            && $bindings->change($ssh, $bindings->revision($ssh), null), 'Explicit Relay detach failed.');
        $administration->setEnabled($relay, $relay->lifecycle_revision, false);
        $wp->refresh();
        $relay->refresh();
        $current = TargetCredential::query()->findOrFail($credential->id);
        $check($wp->transportKind() === 'direct' && ! $relay->enabled
            && ! Target::query()->where('relay_record_id', $relay->id)->exists()
            && $current->dispatchFingerprint() === $credential->dispatchFingerprint(),
            'Detach changed credential authority/material or left an assigned Relay.');

        return ['explicit_direct_restored' => true, 'relay_disabled_unassigned' => true,
            'wp_credential_unchanged' => true];
    }

    throw new RuntimeException('Unsupported installed Relay seed operation.');
}
