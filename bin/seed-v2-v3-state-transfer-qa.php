<?php

declare(strict_types=1);
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use Illuminate\Encryption\Encrypter;
use phpseclib4\Crypt\EC;

/** Disposable synthetic data only, no external provider requests. */
require __DIR__.'/../vendor/autoload.php';

$opt = getopt('', ['source:', 'destination:', 'socket:']);
$source = (string) ($opt['source'] ?? '');
$dest = (string) ($opt['destination'] ?? '');
$socket = (string) ($opt['socket'] ?? '');
foreach ([$source, $dest] as $schema) {
    if (preg_match('/^achgw_qa_[a-z0-9_]+$/D', $schema) !== 1) {
        throw new RuntimeException('Fixture seeding is restricted to achgw_qa_* databases.');
    }
}
if ($source === $dest || ! str_starts_with($socket, '/')) {
    throw new RuntimeException('Distinct QA schemas and absolute socket required.');
}

$db = new PDO('mysql:unix_socket='.$socket.';dbname='.$source.';charset=utf8mb4', 'root', '', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$new = new PDO('mysql:unix_socket='.$socket.';dbname='.$dest.';charset=utf8mb4', 'root', '', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$crypt = new Encrypter(str_repeat("\0", 32), 'AES-256-CBC');
/** @param array<string,mixed> $values */
function ins(PDO $db, string $table, array $values): void
{
    $keys = array_keys($values);
    $sql = 'INSERT INTO '.chr(96).$table.chr(96).' ('.implode(',', array_map(fn ($x) => chr(96).$x.chr(96), $keys)).') VALUES ('.implode(',', array_fill(0, count($keys), '?')).')';
    $db->prepare($sql)->execute(array_values($values));
}
foreach ([$db, $new] as $connection) {
    if ((int) $connection->query('SELECT COUNT(*) FROM users')->fetchColumn() !== 0
        || (int) $connection->query('SELECT COUNT(*) FROM targets')->fetchColumn() !== 0) {
        throw new RuntimeException('QA fixture must start with empty Users and Targets.');
    }
}
$owner = ['id' => 1, 'name' => 'QA Owner', 'email' => 'qa.owner@example.test', 'password' => password_hash('synthetic-old-owner-only', PASSWORD_BCRYPT), 'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => 1, 'ai_access_enabled' => 1];
$admin = ['id' => 2, 'name' => 'QA Administrator', 'email' => 'qa.admin@example.test', 'password' => password_hash('synthetic-old-admin-only', PASSWORD_BCRYPT), 'role' => 'administrator', 'target_scope_mode' => 'selected', 'access_enabled' => 1, 'ai_access_enabled' => 1];
ins($db, 'users', $owner);
ins($db, 'users', $admin);
ins($new, 'users', [...$owner, 'password' => password_hash('synthetic-new-owner-only', PASSWORD_BCRYPT), 'self_created_target_access' => 0]);
$db->exec("UPDATE operational_settings SET overrides='{\"ssh_command_timeout_seconds\":55}',version=4,changed_by=1 WHERE id=1");
$db->exec('UPDATE operational_settings SET ssh_command_timeout_seconds=55 WHERE id=1');
$rel = '01J00000000000000000000001';
$ssh = '01J00000000000000000000002';
$wp = '01J00000000000000000000003';
$arvan = '01J00000000000000000000004';
$group = '01J00000000000000000000005';
$sshCred = '01J00000000000000000000006';
$wpCred = '01J00000000000000000000007';
$arvanCred = '01J00000000000000000000008';
$key = EC::createKey('Ed25519');
$relayPublic = implode(' ', array_slice(preg_split('/\s+/', trim($key->getPublicKey()->toString('OpenSSH'))), 0, 2));
$relayPrivate = $key->toString('OpenSSH');
$relayPayload = ['v' => 1, 'relay_record_id' => $rel, 'relay_id' => 'qa-relay', 'private' => $relayPrivate];
ins($db, 'connection_relays', [
    'id' => $rel, 'relay_id' => 'qa-relay', 'display_name' => 'QA Relay', 'control_host' => 'relay.qa.example.test',
    'control_port' => 2222, 'control_user' => 'qauser', 'control_host_key' => 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHQA',
    'local_socks_port' => 18902, 'enabled' => 1, 'login_public_key' => $relayPublic,
    'login_private_key_encrypted' => $crypt->encryptString(json_encode($relayPayload, JSON_THROW_ON_ERROR)),
]);
foreach ([
    [$ssh, 'qa-ssh', 'ssh_direct', 'QA SSH', $rel],
    [$wp, 'qa-wp', 'wp_ai_bridge', 'QA WordPress', null],
    [$arvan, 'qa-arvan', 'arvancloud', 'QA Arvan', null],
] as [$id,$slug,$type,$name,$relayId]) {
    ins($db, 'targets', ['id' => $id, 'target_id' => $slug, 'display_name' => $name,
        'connector_type' => $type, 'connection_state' => 'connected', 'relay_record_id' => $relayId, 'relay_binding_revision' => $relayId !== null ? 1 : 0]);
}
$hostPin = EC::createKey('Ed25519')->getPublicKey()->toString('OpenSSH');
$hostPin = implode(' ', array_slice(preg_split('/\s+/', $hostPin), 0, 2));
$canonical = SshHostKeyPin::fromLine($hostPin)->canonicalLine();
ins($db, 'ssh_direct_target_configs', [
    'id' => '01J00000000000000000000009', 'target_record_id' => $ssh,
    'host' => 'ssh.qa.example.test', 'port' => 2022, 'username' => 'root', 'auth_method' => 'password',
    'pinned_host_key' => $canonical,
]);
$binding = hash('sha256', implode("\0", [$ssh, 'qa-ssh', 'ssh.qa.example.test', '2022', 'root', 'password', $canonical, 'connection_relay', $rel, '1']));
$sshCipher = $crypt->encryptString(json_encode([
    'v' => 1, 'target_record_id' => $ssh, 'target_id' => 'qa-ssh', 'connector_type' => 'ssh_direct',
    'purpose' => 'ssh_auth', 'binding' => $binding, 'auth_method' => 'password', 'secret' => 'local-qa-only', 'passphrase' => null,
], JSON_THROW_ON_ERROR));
ins($db, 'target_credentials', ['id' => $sshCred, 'target_record_id' => $ssh, 'connector_type' => 'ssh_direct', 'purpose' => 'ssh_auth', 'encrypted_payload' => $sshCipher]);
$client = 'qa-wordpress-client';
$resource = 'https://wordpress.qa.example.test/mcp';
$bind = hash('sha256', $wp."\0".'qa-wp'."\0".$client."\0".$resource);
$wpCipher = $crypt->encryptString(json_encode([
    'v' => 1, 'target_record_id' => $wp, 'target_id' => 'qa-wp', 'connector_type' => 'wp_ai_bridge',
    'purpose' => 'wordpress_oauth', 'client_id' => $client, 'resource_url' => $resource,
    'access_token' => 'synthetic-access-token', 'refresh_token' => 'synthetic-refresh-token',
    'access_expires_at' => '2035-01-01T00:00:00+00:00', 'scopes' => ['read'],
], JSON_THROW_ON_ERROR));
ins($db, 'target_credentials', ['id' => $wpCred, 'target_record_id' => $wp, 'connector_type' => 'wp_ai_bridge', 'purpose' => 'wordpress_oauth', 'encrypted_payload' => $wpCipher]);
ins($db, 'wp_ai_bridge_credential_metadata', [
    'credential_id' => $wpCred, 'client_id' => $client, 'resource_url' => $resource, 'binding_hash' => $bind,
    'access_expires_at' => '2035-01-01 00:00:00', 'refresh_expires_at' => '2035-01-01 00:00:00',
    'refresh_due_at' => '2025-01-01 00:00:00',
]);
ins($db, 'wp_ai_bridge_target_configs', [
    'id' => '01J00000000000000000000010', 'target_record_id' => $wp,
    'base_url' => 'https://wordpress.qa.example.test', 'base_url_hash' => hash('sha256', 'https://wordpress.qa.example.test'),
    'mcp_resource_url' => $resource, 'oauth_issuer_url' => 'https://wordpress.qa.example.test',
    'oauth_authorization_url' => 'https://wordpress.qa.example.test/authorize',
    'oauth_token_url' => 'https://wordpress.qa.example.test/token',
    'oauth_revocation_url' => 'https://wordpress.qa.example.test/revoke',
]);
ins($db, 'arvan_api_target_configs', ['id' => '01J00000000000000000000011', 'target_record_id' => $arvan,
    'base_url' => 'https://api.arvancloud.ir', 'spec_url' => null, 'probe_path' => null]);
$arvanCipher = $crypt->encryptString(json_encode([
    'v' => 1, 'purpose' => 'arvan_api_key', 'connector_type' => 'arvancloud',
    'target_record_id' => $arvan, 'target_id' => 'qa-arvan',
    'base_url' => 'https://api.arvancloud.ir', 'api_key' => 'synthetic-arvan-key',
], JSON_THROW_ON_ERROR));
ins($db, 'target_credentials', ['id' => $arvanCred, 'target_record_id' => $arvan, 'connector_type' => 'arvancloud', 'purpose' => 'arvan_api_key', 'encrypted_payload' => $arvanCipher]);
ins($db, 'target_groups', ['id' => $group, 'name' => 'QA operators']);
ins($db, 'target_group_targets', ['id' => 1, 'target_group_id' => $group, 'target_record_id' => $ssh]);
ins($db, 'target_group_users', ['id' => 1, 'target_group_id' => $group, 'user_id' => 2]);
ins($db, 'target_group_permission_denials', ['id' => 1, 'target_group_id' => $group, 'permission' => 'ssh.command.run']);
ins($db, 'user_permission_denials', ['id' => 1, 'user_id' => 2, 'permission' => 'targets.remove']);
ins($db, 'user_target_access', ['id' => 1, 'user_id' => 2, 'target_record_id' => $ssh, 'allowed' => 1]);
ins($db, 'operational_setting_changes', ['id' => '01J00000000000000000000012', 'setting_key' => 'ssh_command_timeout_seconds',
    'previous_value' => null, 'new_value' => 55, 'version' => 4, 'actor_user_id' => 1, 'created_at' => '2025-01-01 00:00:00']);
ins($db, 'activity_events', [
    'id' => '01J00000000000000000000013', 'correlation_id' => '00000000-0000-4000-8000-000000000001',
    'actor_type' => 'user', 'actor_id' => '2', 'target_id' => 'qa-ssh', 'operation' => 'ssh.inspect',
    'outcome' => 'completed', 'target_record_id' => $ssh, 'created_at' => '2025-01-01 00:00:00',
]);
ins($db, 'ssh_reverse_gateway_settings', [
    'id' => 1, 'enabled' => 1, 'publication_pending' => 0,
    'control_host' => 'reverse.qa.example.test', 'control_port' => 2222,
    'control_user' => 'qa', 'control_host_key' => $canonical, 'revision' => 1,
]);
ins($db, 'ssh_reverse_managed_retired_ports', ['listener_port' => 19100, 'target_id' => 'retired.qa', 'retired_at' => '2025-01-01 00:00:00']);
ins($db, 'ssh_command_jobs', [
    'id' => '01J00000000000000000000020', 'target_record_id' => $ssh, 'user_id' => 2,
    'client_identity_hash' => str_repeat('f', 64), 'request_id' => '00000000-0000-4000-8000-000000000020',
    'script_digest' => str_repeat('e', 64), 'target_binding_hash' => str_repeat('d', 64),
    'status' => 'completed', 'runtime_seconds' => 10, 'expires_at' => '2035-01-01 00:00:00',
]);
$authId = '01J00000000000000000000021';
$oldClient = 'legacy-chatgpt-qa-only';
$oldResource = 'https://old.qa.example.test/mcp';
ins($db, 'oauth_authorizations', [
    'id' => $authId, 'user_id' => 1, 'client_id' => $oldClient,
    'resource' => $oldResource, 'resource_hash' => hash('sha256', $oldResource),
    'scopes' => '["read"]', 'client_profile_key' => 'chatgpt',
]);
ins($db, 'oauth_access_tokens', [
    'id' => 'old-qa-access-token', 'authorization_id' => $authId,
    'client_id' => $oldClient, 'user_id' => 1, 'resource' => $oldResource,
    'scopes' => '["read"]', 'expires_at' => '2035-01-01 00:00:00',
]);
ins($db, 'oauth_refresh_tokens', [
    'id' => 'old-qa-refresh-token', 'access_token_id' => 'old-qa-access-token',
    'authorization_id' => $authId, 'client_id' => $oldClient, 'user_id' => 1,
    'resource' => $oldResource, 'expires_at' => '2035-01-01 00:00:00',
]);
echo "QA_FIXTURE_READY=3_TARGETS_3_CREDENTIALS_1_RELAY_1_OLD_JOB_OLD_OAUTH\n";
