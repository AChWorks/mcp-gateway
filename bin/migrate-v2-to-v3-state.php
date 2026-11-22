<?php

declare(strict_types=1);

/**
 * One-time, repeatable data-only transfer for matching MCP Gateway v2/v3 MariaDB schemas.
 * The old OAuth/ChatGPT identity, SSH Jobs, maintenance state and v3 bootstrap are excluded.
 * No external/remote SSH, WordPress or Arvan provider operations are performed.
 */
ini_set('display_errors', 'stderr');
error_reporting(E_ALL);

$opt = getopt('', ['source:', 'destination:', 'mode:', 'socket::']);
$source = (string) ($opt['source'] ?? '');
$dest = (string) ($opt['destination'] ?? '');
$mode = (string) ($opt['mode'] ?? 'plan');
$socket = (string) ($opt['socket'] ?? '/tmp/mysql.sock');

function check(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}
function quoteId(string $id): string
{
    check((bool) preg_match('/^[A-Za-z0-9_-]+$/D', $id), 'Invalid SQL identifier.');

    return chr(96).str_replace(chr(96), chr(96).chr(96), $id).chr(96);
}
function tableName(string $schema, string $table): string
{
    return quoteId($schema).'.'.quoteId($table);
}
function rows(PDO $pdo, string $sql): array
{
    return $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
}
function countTable(PDO $pdo, string $schema, string $table): int
{
    return (int) $pdo->query('SELECT COUNT(*) FROM '.tableName($schema, $table))->fetchColumn();
}
function dbColumns(PDO $pdo, string $schema, string $table): array
{
    $stmt = $pdo->prepare('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY ORDINAL_POSITION');
    $stmt->execute([$schema, $table]);

    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}
function pkColumns(PDO $pdo, string $schema, string $table): array
{
    $stmt = $pdo->prepare("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_KEY='PRI' ORDER BY ORDINAL_POSITION");
    $stmt->execute([$schema, $table]);

    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}
function joinPk(array $pk): string
{
    return implode(' AND ', array_map(fn ($k) => 'd.'.quoteId($k).' = s.'.quoteId($k), $pk));
}
function sharedColumns(PDO $pdo, string $source, string $dest, string $table): array
{
    $src = dbColumns($pdo, $source, $table);
    $dst = dbColumns($pdo, $dest, $table);
    check($src !== [] && $dst !== [], "Missing table: $table");
    $notInDest = array_diff($src, $dst);
    check($notInDest === [], 'Legacy source columns not present in v3: '.$table);

    return $src;
}
function compareRecords(PDO $pdo, string $source, string $dest, string $table, array $columns, string $where = '1=1'): int
{
    $pk = pkColumns($pdo, $source, $table);
    check($pk !== [], 'Missing source primary key: '.$table);
    $missing = 'd.'.quoteId($pk[0]).' IS NULL';
    $notEqual = array_map(fn ($c) => 'NOT (s.'.quoteId($c).' <=> d.'.quoteId($c).')', $columns);
    $sql = 'SELECT COUNT(*) FROM '.tableName($source, $table).' s LEFT JOIN '.tableName($dest, $table).' d ON '.joinPk($pk)
       .' WHERE ('.$where.') AND ('.$missing.' OR '.implode(' OR ', $notEqual).')';

    return (int) $pdo->query($sql)->fetchColumn();
}
function copyRows(PDO $pdo, string $source, string $dest, string $table, array $columns, string $where = '1=1', array $extra = []): int
{
    $pk = pkColumns($pdo, $source, $table);
    check($pk !== [], 'Missing primary key: '.$table);
    $fields = array_merge($columns, array_keys($extra));
    $selects = array_map(fn ($c) => 's.'.quoteId($c), $columns);
    foreach ($extra as $value) {
        $selects[] = $value;
    }
    $sql = 'INSERT INTO '.tableName($dest, $table).' ('.implode(',', array_map('quoteId', $fields)).')'
       .' SELECT '.implode(',', $selects).' FROM '.tableName($source, $table).' s'
       .' WHERE ('.$where.') AND NOT EXISTS (SELECT 1 FROM '.tableName($dest, $table).' d WHERE '.joinPk($pk).')';

    return $pdo->exec($sql);
}
function sameOwner(PDO $pdo, string $source, string $dest): void
{
    $old = rows($pdo, 'SELECT id,email,role FROM '.tableName($source, 'users')." WHERE role='owner'");
    $new = rows($pdo, 'SELECT id,email,role FROM '.tableName($dest, 'users')." WHERE role='owner'");
    check(count($old) === 1 && count($new) === 1, 'Require exactly one Owner per installation.');
    check($old[0]['id'] === $new[0]['id'] && strcasecmp($old[0]['email'], $new[0]['email']) === 0, 'Owner identity/ID differs: explicit remap required.');
}
function settingsSync(PDO $pdo, string $source, string $dest, array $cols): void
{
    check(countTable($pdo, $source, 'operational_settings') === 1, 'Source setting singleton absent.');
    check(countTable($pdo, $dest, 'operational_settings') === 1, 'Destination setting singleton absent.');
    $oldCols = array_values(array_diff($cols, ['id']));
    $set = implode(',', array_map(fn ($c) => 'd.'.quoteId($c).'=s.'.quoteId($c), $oldCols));
    $affected = $pdo->exec('UPDATE '.tableName($dest, 'operational_settings').' d INNER JOIN '.tableName($source, 'operational_settings').' s ON d.id=s.id SET '.$set);
    check($affected !== false, 'Could not synchronize compatible operational settings.');
}

check($source !== '' && $dest !== '' && $source !== $dest, 'Specify distinct --source and --destination.');
check(in_array($mode, ['plan', 'migrate', 'verify'], true), 'Invalid --mode. Use plan, migrate or verify.');
check(str_starts_with($socket, '/'), 'Expected absolute local MariaDB socket.');

$pdo = new PDO('mysql:unix_socket='.$socket.';charset=utf8mb4', 'root', '', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
]);
$pdo->exec("SET SESSION sql_mode = 'STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'");
$pdo->exec('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');

/**
 * Dependency order is deliberate, including v2 record IDs embedded in encrypted
 * Target and Relay ciphertext. Never recreate those identities or open a Job.
 */
$copyOrder = [
    'users',
    'connection_relays',
    'targets',
    'target_groups',
    'ssh_reverse_gateway_settings',
    'ssh_reverse_managed_retired_ports',
    'ssh_direct_target_configs',
    'wp_ai_bridge_target_configs',
    'arvan_api_target_configs',
    'target_credentials',
    'wp_ai_bridge_credential_metadata',
    'target_group_targets',
    'target_group_users',
    'target_group_permission_denials',
    'user_target_access',
    'user_permission_denials',
    'user_target_permission_denials',
    'wordpress_publish_group_grants',
    'operational_settings',
    'operational_setting_changes',
    'activity_events',
];
$exclude = [
    'migrations',
    'ssh_command_jobs',
    'activity_retention_state',
    'chatgpt_file_admission_guard',
    'chatgpt_file_admission_leases',
    'oauth_access_tokens',
    'oauth_authorizations',
    'oauth_auth_codes',
    'oauth_client_assertions',
    'oauth_client_profiles',
    'oauth_dcr_clients',
    'oauth_refresh_recoveries',
    'oauth_refresh_tokens',
    'password_reset_tokens',
    'target_check_operations',
    'target_check_operation_targets',
    'ssh_reverse_managed_enrollments',
    'wp_ai_bridge_oauth_flows',
    'wp_ai_bridge_refresh_intents',
    'wp_ai_bridge_revocation_intents',
    'wp_ai_bridge_target_reservations',
];
$pdo->beginTransaction();
try {
    sameOwner($pdo, $source, $dest);
    $srcTables = rows($pdo, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='.$pdo->quote($source).' ORDER BY TABLE_NAME');
    $actual = array_column($srcTables, 'TABLE_NAME');
    $unknown = array_diff($actual, array_merge($copyOrder, $exclude));
    check($unknown === [], 'Unclassified source tables: '.implode(',', $unknown));
    $notPresent = array_diff($copyOrder, $actual);
    check($notPresent === [], 'Required source tables missing: '.implode(',', $notPresent));
    $originalOwnerPassword = (string) $pdo->query('SELECT password FROM '.tableName($dest, 'users').' WHERE role = '.$pdo->quote('owner'))->fetchColumn();

    $tablesToCheck = [];
    foreach ($copyOrder as $table) {
        $cols = sharedColumns($pdo, $source, $dest, $table);
        $where = $table === 'users' ? "s.role <> 'owner'" : '1=1';
        $tablesToCheck[$table] = [$cols, $where];
        $src = countTable($pdo, $source, $table);
        $dst = countTable($pdo, $dest, $table);
        echo "table=$table source=$src destination_before=$dst\n";
    }
    foreach ($exclude as $table) {
        $src = in_array($table, $actual, true) ? countTable($pdo, $source, $table) : 0;
        echo "excluded=$table source=$src\n";
    }
    if ($mode === 'migrate') {
        // In-flight provider/Target state cannot be safely resumed on a new issuer.
        // A nonempty legacy queue or flow needs explicit operator reconciliation.
        foreach ([
            'target_check_operations',
            'target_check_operation_targets',
            'ssh_reverse_managed_enrollments',
            'wp_ai_bridge_oauth_flows',
            'wp_ai_bridge_refresh_intents',
            'wp_ai_bridge_revocation_intents',
            'wp_ai_bridge_target_reservations',
        ] as $transient) {
            check(countTable($pdo, $source, $transient) === 0,
                'Outstanding non-ChatGPT transient requires review before import: '.$transient);
        }
        // Fresh-v3-only: never combine two initialized, independently populated vaults.
        check(countTable($pdo, $dest, 'targets') === 0 || countTable($pdo, $dest, 'targets') === countTable($pdo, $source, 'targets'), 'Destination contains independent Targets.');
        check(countTable($pdo, $dest, 'oauth_access_tokens') === 0 && countTable($pdo, $dest, 'oauth_authorizations') === 0 &&
              countTable($pdo, $dest, 'oauth_refresh_tokens') === 0 && countTable($pdo, $dest, 'oauth_refresh_recoveries') === 0 &&
              countTable($pdo, $dest, 'oauth_dcr_clients') === 0, 'Destination has active OAuth state that needs a separate key decision.');
        foreach ($tablesToCheck as $table => [$cols,$where]) {
            if ($table === 'operational_settings') {
                settingsSync($pdo, $source, $dest, $cols);
                echo "synced=$table\n";

                continue;
            }
            $extra = $table === 'users' ? ['self_created_target_access' => '0'] : [];
            $added = copyRows($pdo, $source, $dest, $table, $cols, $where, $extra);
            echo "inserted=$table rows=$added\n";
        }
    }
    if ($mode !== 'plan') {
        foreach ($tablesToCheck as $table => [$cols,$where]) {
            $bad = compareRecords($pdo, $source, $dest, $table, $cols, $where);
            check($bad === 0, 'Data fidelity mismatch in '.$table.' count='.$bad);
            echo "verified=$table mismatches=0\n";
        }
        $newOwnerPassword = (string) $pdo->query('SELECT password FROM '.tableName($dest, 'users').' WHERE role = '.$pdo->quote('owner'))->fetchColumn();
        check(hash_equals($originalOwnerPassword, $newOwnerPassword), 'Fresh v3 Owner password unexpectedly modified.');
        foreach (['oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_authorizations', 'ssh_command_jobs', 'target_batches', 'target_batch_items'] as $t) {
            check(countTable($pdo, $dest, $t) === 0, 'Unexpected old active runtime data in destination: '.$t);
        }
    }
    if ($mode === 'migrate') {
        $pdo->commit();
        echo "RESULT=TRANSFER_COMMITTED\n";
    } else {
        $pdo->rollBack();
        echo 'RESULT='.strtoupper($mode)."_READ_ONLY\n";
    }
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    fwrite(STDERR,'RESULT=FAILED '.get_class($e).' '.$e->getMessage()."\n");
    exit(1);
}
