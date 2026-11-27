<?php

// Run against the extracted, disposable installed-package database only.
// Seed through the installed release's native vaults, not candidate mocks.
use App\Application\Batch\TargetBatchBinding;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetConfig;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetVault;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetVault;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

$mode = $argv[2] ?? '';
if (! in_array($mode, ['seed', 'verify', 'digest', 'schema', 'observations', 'restart', 'interrupt'], true)
    || $argc !== ($mode === 'interrupt' ? 6 : 4)) {
    throw new RuntimeException('Invalid populated migration fixture invocation.');
}
chdir($argv[1]);
require 'vendor/autoload.php';
$app = require 'bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

function requireFixture(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

requireFixture(app()->environment('testing') && config('database.default') === 'mysql'
    && config('database.connections.mysql.host') === '127.0.0.1'
    && preg_match('/^[a-z0-9_]+_test$/D', DB::getDatabaseName()) === 1,
    'Only the disposable installed-package database is accepted.');

function fixtureId(): string
{
    return (string) Str::ulid();
}

function fixtureInsert(string $table, array $fields): void
{
    DB::table($table)->insert(['created_at' => now(), 'updated_at' => now(), ...$fields]);
}

function fixtureTarget(string $slug, string $type, string $state, array $fields = []): Target
{
    $id = fixtureId();
    fixtureInsert('targets', ['id' => $id, 'target_id' => $slug, 'display_name' => $slug,
        'connector_type' => $type, 'connection_state' => $state, ...$fields]);

    return Target::query()->findOrFail($id);
}

function fixtureCredential(Target $target, string $purpose, string $ciphertext, int $revision = 0): TargetCredential
{
    $id = fixtureId();
    $fields = Schema::hasColumn('target_credentials', 'authority_revision') ? ['authority_revision' => $revision] : [];
    fixtureInsert('target_credentials', ['id' => $id, 'target_record_id' => $target->id,
        'connector_type' => $target->connector_type, 'purpose' => $purpose, 'encrypted_payload' => $ciphertext, ...$fields]);

    return TargetCredential::query()->findOrFail($id);
}

function fixtureRows(string $table): array
{
    $rows = DB::table($table)->get()->map(static function ($row): array {
        $row = (array) $row;
        ksort($row);

        return $row;
    })->all();
    usort($rows, static fn ($a, $b) => strcmp(json_encode($a, JSON_THROW_ON_ERROR), json_encode($b, JSON_THROW_ON_ERROR)));

    return $rows;
}

function fixtureDigest(bool $schemaOnly = false): string
{
    $tables = DB::select('SHOW FULL TABLES WHERE Table_type = "BASE TABLE"');
    $names = array_map(static fn ($row) => (string) array_values((array) $row)[0], $tables);
    sort($names);
    $data = [];
    foreach ($names as $name) {
        requireFixture(preg_match('/^[a-z0-9_]+$/D', $name) === 1, 'Unexpected fixture table name.');
        $ddl = array_values((array) DB::selectOne('SHOW CREATE TABLE '.$name))[1];
        $data[$name] = $schemaOnly
            ? preg_replace('/ AUTO_INCREMENT=\d+/', '', $ddl)
            : ['schema' => $ddl, 'rows' => fixtureRows($name)];
    }

    return hash('sha256', json_encode($data, JSON_THROW_ON_ERROR));
}

function fixtureOpen(Target $target, TargetCredential $credential): array|string
{
    return match ($target->connector_type) {
        'ssh_direct' => app(SshTargetVault::class)->open($target,
            SshTargetConfig::query()->where('target_record_id', $target->id)->sole(), $credential),
        'wp_ai_bridge' => app(WpAiBridgeTargetVault::class)->openCredential($target, $credential),
        'arvancloud' => app(ArvanApiTargetVault::class)->open($target,
            ArvanApiTargetConfig::query()->where('target_record_id', $target->id)->sole(), $credential),
    };
}

function fixtureBatch(Target $target, int $actor, string $state, string $binding, bool $exact): string
{
    $batch = fixtureId();
    $ssh = $target->connector_type === 'ssh_direct';
    $claimed = $state !== 'queued';
    $finished = $state === 'completed';
    $turn = $claimed ? ((int) DB::table('target_batches')->max('last_dispatch_turn') + 1) : 0;
    fixtureInsert('target_batches', [
        'id' => $batch, 'actor_user_id' => $actor, 'source_channel' => 'web',
        'client_identity_hash' => hash('sha256', 'installed-fixture'), 'request_id' => (string) Str::uuid(),
        'request_fingerprint' => hash('sha256', $batch), 'request_intent_hash' => hash('sha256', 'intent-'.$batch),
        'capability_key' => $ssh ? 'ssh.command.run' : 'wordpress.bridge.info',
        'arguments_ciphertext' => Crypt::encryptString(json_encode($ssh ? ['command' => 'printf fixture', 'timeout_seconds' => 10] : [], JSON_THROW_ON_ERROR)),
        'status' => $finished ? 'completed' : ($claimed ? 'running' : 'queued'),
        'last_dispatch_turn' => $turn, 'finished_at' => $finished ? now() : null,
        'execution_mode' => 'rolling', 'parallelism' => 1, 'target_count' => 1,
    ]);
    $id = fixtureId();
    fixtureInsert('target_batch_items', [
        'id' => $id, 'batch_id' => $batch, 'target_record_id' => $target->id,
        'target_id_snapshot' => $target->target_id, 'connector_type_snapshot' => $target->connector_type,
        'target_binding_hash' => $exact ? $binding : hash('sha256', 'obsolete-'.$binding),
        'position' => 0, 'status' => $state, 'dispatch_attempt_id' => $state === 'queued' ? null : (string) Str::uuid(),
        'started_at' => $claimed ? now() : null, 'lease_expires_at' => $claimed ? now()->addMinutes(3) : null,
        'finished_at' => $finished ? now() : null, 'diagnostic_reference' => $finished ? (string) Str::uuid() : null,
        'result_ciphertext' => $finished ? Crypt::encryptString(json_encode(['ok' => true, 'status' => 'completed', 'result' => $ssh ? ['exit_code' => 0, 'stdout' => 'fixture'] : ['fixture' => true]], JSON_THROW_ON_ERROR)) : null,
    ]);

    return $id;
}

/**
 * Real executed SQL boundaries, not simulated migration objects. The child
 * exits before Laravel can write its migration-ledger entry. Closing its DB
 * connection rolls back uncommitted DML but cannot undo MariaDB DDL.
 */
function fixtureInterruptions(): array
{
    return [
        '0001_01_01_000003_preserve_delegated_permission_boundaries' => [['insert ignore into user_permission_denials', 1]],
        '0001_01_01_000004_detach_ssh_login_from_transport' => [['update target_credentials', 1]],
        '0001_01_01_000005_move_reverse_to_target_transport' => [['alter table targets rename column relay_binding_revision', 1]],
        '0001_01_01_000006_add_credential_authority_revision' => [['alter table target_credentials add authority_revision', 1]],
        '0001_01_01_000007_bind_queued_batches_to_credential_authority' => [['update target_batch_items', 2]],
        '0001_01_01_000008_record_batch_dispatch_evidence' => [['alter table target_batch_items add effect_admitted', 1]],
        '0001_01_01_000009_record_ssh_job_attempt_evidence' => [['alter table ssh_command_jobs add original_peer_fingerprint', 1]],
        '0001_01_01_000010_record_target_check_evidence' => [
            ['create table target_check_evidence', 1],
            ['insert ignore into target_check_evidence', 1],
            ['update targets set last_error_check_kind', 1],
        ],
    ];
}

function fixtureAssertOwnedDatabase(string $snapshot): void
{
    $data = json_decode(file_get_contents($snapshot), true, 512, JSON_THROW_ON_ERROR);
    foreach ($data['targets'] as $id => $unused) {
        requireFixture(DB::table('targets')->where('id', $id)->where('target_id', 'like', 'qa-pop-%')->exists(),
            'Interrupted migration fixture must own the exact populated test database.');
    }
    requireFixture(count($data['targets']) > 0, 'Missing populated fixture identity.');
}

if ($mode === 'digest' || $mode === 'schema') {
    echo fixtureDigest($mode === 'schema');
    exit(0);
}

if ($mode === 'observations') {
    echo hash('sha256', json_encode(fixtureRows('target_check_evidence'), JSON_THROW_ON_ERROR));
    exit(0);
}

if ($mode === 'interrupt') {
    fixtureAssertOwnedDatabase($argv[3]);
    $migration = $argv[4];
    $boundary = (int) $argv[5];
    [$prefix, $occurrence] = fixtureInterruptions()[$migration][$boundary] ?? throw new RuntimeException('Unknown migration checkpoint.');
    requireFixture(! DB::table('migrations')->where('migration', $migration)->exists(), 'Migration already recorded.');
    $seen = 0;
    DB::listen(static function (QueryExecuted $query) use ($prefix, $occurrence, &$seen): void {
        $sql = strtolower(str_replace(chr(96), '', $query->sql));
        if (str_starts_with($sql, $prefix) && ++$seen === $occurrence) {
            echo 'INTERRUPTED after executed SQL: '.$prefix.' #'.$occurrence."\n";
            exit(86);
        }
    });
    Artisan::call('migrate', ['--force' => true, '--path' => 'database/migrations/'.$migration.'.php']);
    throw new RuntimeException('Expected interruption did not occur: '.$migration.' / '.$prefix);
}

if ($mode === 'restart') {
    fixtureAssertOwnedDatabase($argv[3]);
    $script = __FILE__;
    $snapshot = json_decode(file_get_contents($argv[3]), true, 512, JSON_THROW_ON_ERROR);
    $applied = DB::table('migrations')->pluck('migration')->all();
    $files = app('migrator')->getMigrationFiles(database_path('migrations'));
    foreach ($files as $migration => $path) {
        if (in_array($migration, $applied, true)) {
            continue;
        }
        foreach (fixtureInterruptions()[$migration] ?? [] as $boundary => [$prefix, $occurrence]) {
            $before = $migration === '0001_01_01_000004_detach_ssh_login_from_transport' ? fixtureDigest() : null;
            $queued = $migration === '0001_01_01_000007_bind_queued_batches_to_credential_authority'
                ? DB::table('target_batch_items')->whereIn('id', $snapshot['converted'])->pluck('target_binding_hash', 'id')->all() : null;
            $child = new Process([PHP_BINARY, $script, $argv[1], 'interrupt', $argv[3], $migration, (string) $boundary]);
            $child->setTimeout(60);
            $child->run();
            requireFixture($child->getExitCode() === 86 && str_contains($child->getOutput(), 'INTERRUPTED after executed SQL: '.$prefix),
                'Expected SQL interruption not observed: '.$migration.' / '.$prefix.' (exit '.($child->getExitCode() ?? 'unknown').')');
            echo $child->getOutput();
            requireFixture(! DB::table('migrations')->where('migration', $migration)->exists(), 'Interrupted migration was falsely recorded.');
            if ($before !== null) {
                requireFixture(fixtureDigest() === $before, 'Uncommitted SSH credential conversion did not roll back exactly.');
            }
            if ($queued !== null) {
                $after = DB::table('target_batch_items')->whereIn('id', array_keys($queued))->pluck('target_binding_hash', 'id')->all();
                requireFixture(count(array_diff_assoc($after, $queued)) === 1,
                    'Expected exactly one committed queued authority conversion before interruption.');
            }
            if ($prefix === 'update targets set last_error_check_kind') {
                $target = DB::table('targets')->where('target_id', 'qa-pop-wp-metadata-error')->sole();
                requireFixture($target->last_error_check_kind === null
                    && ! DB::table('target_check_evidence')->where('target_record_id', $target->id)->exists(),
                    'Uncommitted WordPress observation and lifecycle provenance must roll back together.');
            }
        }
        // Resume through the normal installed Artisan entrypoint, not
        // direct calls to up(). This also works when a newer baseline has
        // already recorded part or all of these historical migrations.
        $resume = new Process([PHP_BINARY, 'artisan', 'migrate', '--force', '--no-interaction', '--path=database/migrations/'.$migration.'.php']);
        $resume->setTimeout(60);
        $resume->mustRun();
        requireFixture(DB::table('migrations')->where('migration', $migration)->count() === 1,
            'Resumed migration was not recorded exactly once: '.$migration);
        echo 'PASS: resumed '.$migration."\n";
    }
    requireFixture(array_keys($files) === DB::table('migrations')->orderBy('migration')->pluck('migration')->all(),
        'Migration ledger incomplete after restart.');
    if (Schema::hasTable('target_check_evidence')) {
        requireFixture(collect(Schema::getForeignKeys('target_check_evidence'))->contains(
            static fn (array $key): bool => $key['columns'] === ['target_record_id']
                && $key['foreign_table'] === 'targets' && $key['foreign_columns'] === ['id']
                && $key['on_delete'] === 'cascade',
        ), 'Resumed check-evidence table lost its Target cascade foreign key.');
        DB::transaction(static function (): void {
            $target = fixtureTarget('qa-pop-restart-cascade', 'ssh_direct', 'connected');
            DB::table('target_check_evidence')->insert(['target_record_id' => $target->id, 'kind' => 'ssh_login']);
            DB::table('targets')->where('id', $target->id)->delete();
            requireFixture(! DB::table('target_check_evidence')->where('target_record_id', $target->id)->exists(),
                'Native Target deletion did not cascade after migration restart.');
        });
    }
    echo "PASS: all pending migrations resumed with exact ledger identities.\n";
    exit(0);
}

$legacy = Schema::hasColumn('ssh_direct_target_configs', 'route_mode');
$epoch = $legacy ? 'relay_binding_revision' : 'transport_revision';
$tables = ['wp_ai_bridge_target_configs', 'wp_ai_bridge_credential_metadata', 'wp_ai_bridge_refresh_intents',
    'wp_ai_bridge_revocation_intents', 'wp_ai_bridge_oauth_flows', 'arvan_api_target_configs',
    'connection_relays', 'ssh_reverse_gateway_settings', 'ssh_reverse_managed_retired_ports',
    'target_batches', 'operational_settings', 'oauth_authorizations', 'oauth_access_tokens', 'oauth_refresh_tokens',
    'target_groups', 'target_group_targets', 'target_group_users', 'user_target_access'];
if ($argv[2] === 'seed') {
    $owner = (int) DB::table('users')->where('email', 'gateway-qa-owner@example.test')->value('id');
    requireFixture($owner > 0, 'Installed fixture Owner is missing.');
    $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('a', 32));
    $relay = fixtureId();
    fixtureInsert('connection_relays', ['id' => $relay, 'relay_id' => 'qa-pop-relay',
        'display_name' => 'QA Relay', 'control_host' => 'relay.example.test', 'control_port' => 22,
        'control_user' => 'fixture', 'control_host_key' => $pin, 'local_socks_port' => 18421, 'enabled' => true]);
    $targets = [];
    $converted = [];
    foreach (['direct', 'relay', 'reverse', 'managed'] as $index => $kind) {
        $reverse = in_array($kind, ['reverse', 'managed'], true);
        $route = ['reverse_listener_port' => $reverse ? 18430 + $index : null,
            'reverse_tunnel_identity' => $reverse ? 'qa-'.$kind : null];
        $target = fixtureTarget('qa-pop-'.$kind, 'ssh_direct', 'connected', [
            $epoch => $index, 'relay_record_id' => $kind === 'relay' ? $relay : null,
            'last_tested_at' => now(), 'connected_at' => now(), ...($legacy ? [] : $route),
        ]);
        $config = SshTargetConfig::query()->create(['target_record_id' => $target->id, 'host' => 'ssh.example.test',
            'port' => 22, 'username' => 'fixture', 'auth_method' => 'password', 'pinned_host_key' => $pin,
            'binding_revision' => $index, ...($legacy ? ['route_mode' => $reverse ? 'reverse' : 'direct', ...$route] : [])]);
        $credential = fixtureCredential($target, 'ssh_auth',
            app(SshTargetVault::class)->seal($target, $config, 'fixture-'.$kind, null));
        $targets[$target->id] = ['route' => $route, 'epoch' => $index, 'config_id' => $config->id,
            'credential_id' => $credential->id, 'secret' => fixtureOpen($target, $credential)];
        if ($kind === 'managed') {
            fixtureInsert('ssh_reverse_managed_enrollments', ['id' => fixtureId(), 'target_id' => $target->target_id,
                'target_record_id' => $target->id, 'listener_port' => $route['reverse_listener_port'],
                'tunnel_identity' => $route['reverse_tunnel_identity'], 'control_public_key' => $pin,
                'control_key_hash' => hash('sha256', $pin), 'login_public_key' => $legacy ? $pin : '',
                'state' => 'active', 'activated_at' => now()]);
        }
        $binding = app(TargetBatchBinding::class)->hash($target);
        requireFixture(is_string($binding), 'SSH fixture binding missing.');
        $converted[] = fixtureBatch($target, $owner, 'queued', $binding, true);
        fixtureBatch($target, $owner, 'queued', $binding, false);
        fixtureBatch($target, $owner, 'dispatching', $binding, true);
        fixtureBatch($target, $owner, 'completed', $binding, true);
        fixtureInsert('ssh_command_jobs', ['id' => fixtureId(), 'target_record_id' => $target->id,
            'user_id' => $owner, 'client_identity_hash' => hash('sha256', 'fixture'), 'request_id' => (string) Str::uuid(),
            'script_digest' => hash('sha256', 'fixture job'), 'target_binding_hash' => SshTargetBinding::hash($target, $config),
            'status' => 'launch_unknown', 'unit_mode' => 'user', 'runtime_seconds' => 60,
            'preparing_expires_at' => now()->addMinutes(2), 'reconcile_grace_seconds' => 600,
            'admission_expires_at' => now()->addMinutes(15), 'expires_at' => now()->addDay(),
            'original_user_id' => $owner, 'original_target_record_id' => $target->id, 'original_target_id' => $target->target_id,
            'original_host' => $config->host, 'original_port' => $config->port, 'original_os_username' => $config->username,
            'original_auth_method' => $config->auth_method, 'original_host_key_digest' => hash('sha256', $pin)]);
    }
    DB::table('ssh_reverse_managed_retired_ports')->insert(['listener_port' => 18499, 'target_id' => 'qa-retired', 'retired_at' => now()]);
    $wordpressKinds = ['ready', 'refresh', 'revoke', 'flow'];
    if (! Schema::hasTable('target_check_evidence')) {
        $wordpressKinds[] = 'metadata-error';
    }
    foreach ($wordpressKinds as $kind) {
        $metadataError = $kind === 'metadata-error';
        $failedAt = now()->subMinute();
        $target = fixtureTarget('qa-pop-wp-'.$kind, 'wp_ai_bridge',
            $metadataError ? 'error' : ($kind === 'flow' ? 'pending' : 'connected'),
            $metadataError ? [
                'last_error_code' => 'metadata_unreachable', 'last_failure_code' => 'metadata_unreachable',
                'last_failure_at' => $failedAt, 'last_tested_at' => $failedAt,
            ] : []);
        $base = 'https://'.$kind.'.example.test';
        $resource = $base.'/mcp';
        $client = 'https://gateway.example.test/client.json';
        fixtureInsert('wp_ai_bridge_target_configs', ['id' => fixtureId(), 'target_record_id' => $target->id,
            'base_url' => $base, 'base_url_hash' => hash('sha256', $base), 'mcp_resource_url' => $resource,
            'oauth_issuer_url' => $base, 'oauth_authorization_url' => $base.'/authorize',
            'oauth_token_url' => $base.'/token', 'oauth_revocation_url' => $base.'/revoke',
            'metadata_checked_at' => $metadataError ? now()->subMinutes(2) : now(), 'metadata_reachable' => ! $metadataError]);
        if ($metadataError) {
            continue;
        }
        $vault = app(WpAiBridgeTargetVault::class);
        $expires = now()->addHour();
        if ($kind === 'flow') {
            $state = hash('sha256', 'fixture-flow');
            fixtureInsert('wp_ai_bridge_oauth_flows', ['id' => fixtureId(), 'target_record_id' => $target->id,
                'state_hash' => $state, 'expires_at' => $expires, 'encrypted_context' => $vault->sealFlow($target, $state,
                    ['client_id' => $client, 'redirect_uri' => 'https://gateway.example.test/callback', 'resource_url' => $resource,
                        'issuer_url' => $base, 'token_url' => $base.'/token', 'revocation_url' => $base.'/revoke',
                        'code_verifier' => 'fixture-code-verifier'], $expires->getTimestamp())]);

            continue;
        }
        $credential = fixtureCredential($target, 'wordpress_oauth',
            $vault->sealCredential($target, $client, $resource, 'access-'.$kind, 'refresh-'.$kind, $expires, ['mcp']),
            $kind === 'revoke' ? 1 : 0);
        DB::table('wp_ai_bridge_credential_metadata')->insert(['credential_id' => $credential->id,
            'client_id' => $client, 'resource_url' => $resource,
            'binding_hash' => hash('sha256', $target->id."\0".$target->target_id."\0".$client."\0".$resource),
            'access_expires_at' => $expires, 'refresh_expires_at' => now()->addDay(),
            'refresh_due_at' => now()->addMinutes(30), 'generation' => 7]);
        $targets[$target->id] = ['credential_id' => $credential->id, 'secret' => fixtureOpen($target, $credential),
            'revision' => $kind === 'revoke' ? 1 : 0];
        if ($kind === 'refresh') {
            fixtureInsert('wp_ai_bridge_refresh_intents', ['id' => fixtureId(), 'target_record_id' => $target->id,
                'credential_id' => $credential->id, 'generation' => 7, 'attempts' => 1]);
        } elseif ($kind === 'revoke') {
            fixtureInsert('wp_ai_bridge_revocation_intents', ['id' => fixtureId(), 'target_record_id' => $target->id,
                'kind' => 'disconnect', 'phase' => 'legacy_unknown', 'credential_id' => $credential->id, 'generation' => 7]);
        } else {
            $binding = app(TargetBatchBinding::class)->hash($target);
            requireFixture(is_string($binding), 'WordPress fixture binding missing.');
            $converted[] = fixtureBatch($target, $owner, 'queued', $binding, true);
            fixtureBatch($target, $owner, 'completed', $binding, true);
        }
    }
    $arvan = fixtureTarget('qa-pop-arvan', 'arvancloud', 'connected', ['last_tested_at' => now()]);
    $config = ArvanApiTargetConfig::query()->create(['target_record_id' => $arvan->id,
        'base_url' => 'https://arvan.example.test', 'probe_path' => '/probe']);
    $credential = fixtureCredential($arvan, 'arvan_api_key', app(ArvanApiTargetVault::class)->seal($arvan, $config, 'fixture-arvan'));
    $targets[$arvan->id] = ['credential_id' => $credential->id, 'secret' => fixtureOpen($arvan, $credential)];
    $operator = (int) DB::table('users')->where('email', 'gateway-qa-operator@example.test')->value('id');
    requireFixture($operator > 0, 'Fixture Operator is missing.');
    $group = fixtureId();
    fixtureInsert('target_groups', ['id' => $group, 'name' => 'QA populated group']);
    fixtureInsert('target_group_users', ['target_group_id' => $group, 'user_id' => $operator]);
    fixtureInsert('target_group_targets', ['target_group_id' => $group, 'target_record_id' => $arvan->id]);
    fixtureInsert('user_target_access', ['user_id' => $operator, 'target_record_id' => $arvan->id, 'allowed' => false]);
    $denials = [
        'user_permission_denials' => ['user_id' => $operator],
        'user_target_permission_denials' => ['user_id' => $operator, 'target_record_id' => $arvan->id],
        'target_group_permission_denials' => ['target_group_id' => $group],
    ];
    foreach ($denials as $table => $identity) {
        foreach ($legacy ? ['targets.update'] : ['targets.update', 'targets.configure', 'targets.operations.manage'] as $permission) {
            DB::table($table)->insertOrIgnore(['created_at' => now(), 'updated_at' => now(), ...$identity, 'permission' => $permission]);
        }
    }
    $authorization = DB::table('oauth_authorizations')->where('client_id', 'qa-client')->sole();
    $access = fixtureId();
    $identity = ['authorization_id' => $authorization->id, 'client_id' => $authorization->client_id,
        'user_id' => $owner, 'resource' => $authorization->resource];
    fixtureInsert('oauth_access_tokens', ['id' => $access, ...$identity, 'scopes' => '[]', 'expires_at' => now()->addHour()]);
    fixtureInsert('oauth_refresh_tokens', ['id' => fixtureId(), 'access_token_id' => $access, ...$identity, 'expires_at' => now()->addDay()]);
    DB::table('operational_settings')->where('id', 1)->update([
        'ssh_command_max_kib' => 512, 'batch_dispatch_turn' => 19,
        'overrides' => json_encode(['wp_response_kib' => 128], JSON_THROW_ON_ERROR),
    ]);

    $data = ['legacy' => $legacy, 'targets' => $targets, 'converted' => $converted, 'denials' => $denials, 'rows' => []];
    foreach ([...$tables, 'targets', 'ssh_direct_target_configs', 'target_credentials', 'ssh_reverse_managed_enrollments',
        'target_batch_items', 'ssh_command_jobs'] as $table) {
        $data['rows'][$table] = fixtureRows($table);
    }
    file_put_contents($argv[3], json_encode($data, JSON_THROW_ON_ERROR), LOCK_EX);
    chmod($argv[3], 0600);
    echo "Seeded native SSH, Relay/Reverse, WordPress OAuth, Arvan and retained execution fixtures.\n";
    exit(0);
}

$data = json_decode(file_get_contents($argv[3]), true, 512, JSON_THROW_ON_ERROR);
$upgrade = $data['legacy'] && ! $legacy;
foreach ($data['targets'] as $id => $expected) {
    $target = Target::query()->findOrFail($id);
    $credential = TargetCredential::query()->findOrFail($expected['credential_id']);
    requireFixture(json_encode(fixtureOpen($target, $credential), JSON_THROW_ON_ERROR) === json_encode($expected['secret'], JSON_THROW_ON_ERROR),
        'Native credential recovery failed.');
    if (isset($expected['route'])) {
        $config = SshTargetConfig::query()->findOrFail($expected['config_id']);
        foreach ($expected['route'] as $field => $value) {
            requireFixture(($legacy ? $config->$field : $target->$field) === $value, 'Transport identity changed.');
        }
        requireFixture((int) $target->$epoch === $expected['epoch'], 'Transport generation changed.');
    }
    if (Schema::hasColumn('target_credentials', 'authority_revision')) {
        requireFixture((int) $credential->authority_revision === ($expected['revision'] ?? 0), 'Credential authority changed unexpectedly.');
    }
}
foreach ($data['rows'] as $table => $before) {
    $after = fixtureRows($table);
    // The migration may translate exact queued admissions and SSH envelope
    // bindings, but never dispatched evidence, identities or protocol intents.
    $project = static function (array $rows) use ($table, $upgrade, $data): array {
        foreach ($rows as &$row) {
            if ($upgrade) {
                if ($table === 'targets') {
                    $row['transport_revision'] = $row['transport_revision'] ?? $row['relay_binding_revision'];
                    unset($row['relay_binding_revision'], $row['reverse_listener_port'], $row['reverse_tunnel_identity'], $row['last_error_check_kind']);
                } elseif ($table === 'ssh_direct_target_configs') {
                    unset($row['route_mode'], $row['reverse_listener_port'], $row['reverse_tunnel_identity']);
                } elseif ($table === 'target_credentials') {
                    unset($row['authority_revision']);
                    if ($row['purpose'] === 'ssh_auth' && ($data['targets'][$row['target_record_id']]['epoch'] ?? 0) > 0) {
                        unset($row['encrypted_payload'], $row['updated_at']);
                    }
                } elseif ($table === 'ssh_reverse_managed_enrollments') {
                    unset($row['login_public_key']);
                } elseif ($table === 'target_batch_items') {
                    unset($row['effect_admitted'], $row['late_observation_ciphertext']);
                    if (in_array($row['id'], $data['converted'], true)) {
                        unset($row['target_binding_hash']);
                    }
                } elseif ($table === 'ssh_command_jobs') {
                    unset($row['original_peer_fingerprint'], $row['launch_admitted'], $row['launch_observation_ciphertext']);
                }
            }
            ksort($row);
        }
        unset($row);
        usort($rows, static fn ($a, $b) => strcmp(json_encode($a, JSON_THROW_ON_ERROR), json_encode($b, JSON_THROW_ON_ERROR)));

        return $rows;
    };
    requireFixture($project($before) === $project($after), 'Unexpected persisted mutation in '.$table.'.');
}
foreach ($data['denials'] as $table => $identity) {
    foreach ($legacy ? ['targets.update'] : ['targets.update', 'targets.configure', 'targets.operations.manage'] as $permission) {
        requireFixture(DB::table($table)->where($identity)->where('permission', $permission)->exists(), 'Explicit deny scope lost: '.$table);
    }
}
foreach (DB::table('wp_ai_bridge_oauth_flows')->get() as $flow) {
    requireFixture(app(WpAiBridgeTargetVault::class)->openFlow(Target::query()->findOrFail($flow->target_record_id), $flow)['code_verifier']
        === 'fixture-code-verifier', 'Pending OAuth flow could not be opened.');
}
if ($upgrade) {
    foreach ($data['converted'] as $id) {
        $item = DB::table('target_batch_items')->where('id', $id)->sole();
        $target = Target::query()->findOrFail($item->target_record_id);
        requireFixture($item->target_binding_hash === app(TargetBatchBinding::class)->hash($target), 'Exact queued admission was not translated.');
    }
    requireFixture(DB::table('ssh_reverse_managed_enrollments')->where('target_id', 'qa-pop-managed')->value('login_public_key') === '',
        'Verified managed enrollment kept obsolete bootstrap authority.');
    requireFixture(! DB::table('target_batch_items')->whereNotNull('effect_admitted')->exists()
        && ! DB::table('ssh_command_jobs')->whereNotNull('launch_admitted')->exists()
        && ! DB::table('target_batch_items')->whereNotNull('late_observation_ciphertext')->exists()
        && ! DB::table('ssh_command_jobs')->whereNotNull('original_peer_fingerprint')->exists()
        && ! DB::table('ssh_command_jobs')->whereNotNull('launch_observation_ciphertext')->exists(), 'Legacy dispatch evidence was invented.');
    requireFixture(DB::table('target_check_evidence')->where('kind', 'ssh_login')->count() === 4,
        'Recorded SSH check evidence was not imported exactly.');
    $metadataError = DB::table('targets')->where('target_id', 'qa-pop-wp-metadata-error')->sole();
    $observation = DB::table('target_check_evidence')->where('target_record_id', $metadataError->id)
        ->where('kind', 'wordpress_metadata')->sole();
    requireFixture($metadataError->last_error_check_kind === 'wordpress_metadata'
        && $observation->error_code === 'metadata_unreachable'
        && Carbon::parse($observation->observed_at)->equalTo(Carbon::parse($metadataError->last_tested_at)),
        'Metadata-only error provenance or observation was lost.');
}
echo "Verified populated installed identities, native secrets, protocol intents and retained journals.\n";
