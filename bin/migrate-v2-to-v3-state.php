<?php

declare(strict_types=1);

/**
 * One-time, repeatable data-only transfer for matching MCP Gateway v2/v3 MariaDB schemas.
 * The old OAuth/ChatGPT identity, SSH Jobs, maintenance state and v3 bootstrap are excluded.
 * No external/remote SSH, WordPress or Arvan provider operations are performed.
 */
ini_set('display_errors', 'stderr');
error_reporting(E_ALL);

$opt = getopt('', ['source:', 'destination:', 'mode:', 'socket::',
    'ack-source-quiesced', 'ack-destination-scheduler-paused', 'qa-lock-delay-ms::']);
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
/** @return list<array<string, mixed>> */
function rows(PDO $pdo, string $sql): array
{
    return $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
}
function countTable(PDO $pdo, string $schema, string $table): int
{
    return (int) $pdo->query('SELECT COUNT(*) FROM '.tableName($schema, $table))->fetchColumn();
}
/** @return array<string, string> */
function columnTypes(PDO $pdo, string $schema, string $table): array
{
    $stmt = $pdo->prepare('SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY ORDINAL_POSITION');
    $stmt->execute([$schema, $table]);
    $types = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $field) {
        $types[$field['COLUMN_NAME']] = $field['DATA_TYPE'];
    }

    return $types;
}

/** @return list<string> */
function dbColumns(PDO $pdo, string $schema, string $table): array
{
    return array_keys(columnTypes($pdo, $schema, $table));
}

function byteEqual(string $left, string $right, string $type): string
{
    $textTypes = [
        'char', 'varchar', 'text', 'tinytext', 'mediumtext', 'longtext',
        'enum', 'set', 'binary', 'varbinary', 'blob', 'tinyblob',
        'mediumblob', 'longblob', 'uuid',
    ];

    return in_array($type, $textTypes, true)
        ? '(BINARY '.$left.' <=> BINARY '.$right.')'
        : '('.$left.' <=> '.$right.')';
}

/** @return list<string> */
function pkColumns(PDO $pdo, string $schema, string $table): array
{
    $stmt = $pdo->prepare("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_KEY='PRI' ORDER BY ORDINAL_POSITION");
    $stmt->execute([$schema, $table]);

    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}
/** @param list<string> $pk
 * @param  array<string,string>  $types
 */
function joinPk(array $pk, array $types): string
{
    return implode(' AND ', array_map(
        fn ($k) => byteEqual('d.'.quoteId($k), 's.'.quoteId($k), $types[$k]), $pk
    ));
}

/** @return list<string> */
function sharedColumns(PDO $pdo, string $source, string $dest, string $table): array
{
    $src = dbColumns($pdo, $source, $table);
    $dst = dbColumns($pdo, $dest, $table);
    check($src !== [] && $dst !== [], "Missing table: $table");
    $notInDest = array_diff($src, $dst);
    check($notInDest === [], 'Legacy source columns not present in v3: '.$table);
    $srcTypes = columnTypes($pdo, $source, $table);
    $dstTypes = columnTypes($pdo, $dest, $table);
    foreach ($srcTypes as $column => $type) {
        check(($dstTypes[$column] ?? null) === $type,
            'Incompatible shared field type: '.$table.'.'.$column);
    }

    return $src;
}
/** @param list<string> $columns */
function compareRecords(PDO $pdo, string $source, string $dest, string $table, array $columns, string $where = '1=1'): int
{
    $pk = pkColumns($pdo, $source, $table);
    check($pk !== [], 'Missing source primary key: '.$table);
    $types = columnTypes($pdo, $source, $table);
    $missing = 'd.'.quoteId($pk[0]).' IS NULL';
    $notEqual = array_map(
        fn ($c) => 'NOT '.byteEqual('s.'.quoteId($c), 'd.'.quoteId($c), $types[$c]),
        $columns
    );
    $sql = 'SELECT COUNT(*) FROM '.tableName($source, $table).' s LEFT JOIN '.tableName($dest, $table)
        .' d ON '.joinPk($pk, $types).' WHERE ('.$where.') AND ('.$missing.' OR '.implode(' OR ', $notEqual).')';

    return (int) $pdo->query($sql)->fetchColumn();
}

/** Count destination-only rows, including extra Groups and permission grants. */
function destinationExtra(PDO $pdo, string $source, string $dest, string $table): int
{
    $pk = pkColumns($pdo, $source, $table);
    check($pk !== [], 'Missing primary key: '.$table);
    $types = columnTypes($pdo, $source, $table);
    $where = $table === 'users' ? "d.role <> 'owner' AND " : '';
    $sql = 'SELECT COUNT(*) FROM '.tableName($dest, $table).' d LEFT JOIN '.tableName($source, $table)
        .' s ON '.joinPk($pk, $types).' WHERE '.$where.'s.'.quoteId($pk[0]).' IS NULL';

    return (int) $pdo->query($sql)->fetchColumn();
}

/** Compare existing rows before attempting idempotent insertion. */
/** @param list<string> $columns */
function destinationConflict(PDO $pdo, string $source, string $dest, string $table, array $columns): int
{
    $pk = pkColumns($pdo, $source, $table);
    $types = columnTypes($pdo, $source, $table);
    $notEqual = array_map(
        fn ($c) => 'NOT '.byteEqual('s.'.quoteId($c), 'd.'.quoteId($c), $types[$c]),
        $columns
    );
    $filter = $table === 'users' ? "s.role <> 'owner' AND " : '';
    $sql = 'SELECT COUNT(*) FROM '.tableName($source, $table).' s INNER JOIN '.tableName($dest, $table)
        .' d ON '.joinPk($pk, $types).' WHERE '.$filter.'('.implode(' OR ', $notEqual).')';

    return (int) $pdo->query($sql)->fetchColumn();
}

/**
 * @param  list<string>  $columns
 * @param  array<string, string>  $extra
 */
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
       .' WHERE ('.$where.') AND NOT EXISTS (SELECT 1 FROM '.tableName($dest, $table).' d WHERE '.joinPk($pk, columnTypes($pdo, $source, $table)).')';

    return $pdo->exec($sql);
}
function sameOwner(PDO $pdo, string $source, string $dest): void
{
    $old = rows($pdo, 'SELECT id,email,role FROM '.tableName($source, 'users')." WHERE role='owner'");
    $new = rows($pdo, 'SELECT id,email,role FROM '.tableName($dest, 'users')." WHERE role='owner'");
    check(count($old) === 1 && count($new) === 1, 'Require exactly one Owner per installation.');
    check($old[0]['id'] === $new[0]['id'] && strcasecmp($old[0]['email'], $new[0]['email']) === 0, 'Owner identity/ID differs: explicit remap required.');
}
/** @param list<string> $cols */
function settingsSync(PDO $pdo, string $source, string $dest, array $cols): void
{
    check(countTable($pdo, $source, 'operational_settings') === 1, 'Source setting singleton absent.');
    check(countTable($pdo, $dest, 'operational_settings') === 1, 'Destination setting singleton absent.');
    $legacy = rows($pdo, 'SELECT * FROM '.tableName($source, 'operational_settings').' WHERE id=1');
    check(count($legacy) === 1, 'Source setting ID does not match v3.');
    $columns = array_values(array_diff($cols, ['id']));
    $update = implode(',', array_map(fn ($c) => quoteId($c).'=?', $columns));
    // Updating the destination through a cross-schema UPDATE JOIN can
    // request a writer lock on the source and self-block the source READ
    // fence. Keep the source SELECT and destination UPDATE separate.
    $stmt = $pdo->prepare('UPDATE '.tableName($dest, 'operational_settings').' SET '.$update.' WHERE id=1');
    $stmt->execute(array_map(fn ($c) => $legacy[0][$c], $columns));
}

/** @param list<string> $tables */
function validateTableEngines(PDO $pdo, string $source, string $dest, array $tables): void
{
    $stmt = $pdo->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?');
    foreach ([$source, $dest] as $schema) {
        foreach ($tables as $table) {
            $stmt->execute([$schema, $table]);
            check(strcasecmp((string) $stmt->fetchColumn(), 'InnoDB') === 0,
                'Migration requires transactional InnoDB table: '.$schema.'.'.$table);
        }
    }
}
function assertDestinationAccess(PDO $pdo, string $dest): void
{
    $invalidCreator = (int) $pdo->query('SELECT COUNT(*) FROM '.tableName($dest, 'users')
        ." WHERE role <> 'owner' AND self_created_target_access <> 0")->fetchColumn();
    check($invalidCreator === 0, 'Destination has unexpected expanded non-Owner creator-scope access.');
    $creatorTargets = (int) $pdo->query('SELECT COUNT(*) FROM '.tableName($dest, 'targets')
        .' WHERE created_by_user_id IS NOT NULL')->fetchColumn();
    check($creatorTargets === 0, 'Destination has unexpected v3-only Target creator grants.');
}
function assertNoExistingRuntime(PDO $pdo, string $dest): void
{
    foreach ([
        'oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_authorizations',
        'oauth_auth_codes', 'oauth_client_assertions', 'oauth_refresh_recoveries',
        'oauth_dcr_clients', 'ssh_command_jobs', 'target_batches', 'target_batch_items',
        'target_check_operations', 'target_check_operation_targets',
        'wp_ai_bridge_oauth_flows', 'wp_ai_bridge_refresh_intents',
        'wp_ai_bridge_revocation_intents', 'wp_ai_bridge_target_reservations',
    ] as $table) {
        check(countTable($pdo, $dest, $table) === 0,
            'Unexpected active or independent destination state: '.$table);
    }
}

check($source !== '' && $dest !== '' && $source !== $dest, 'Specify distinct --source and --destination.');
check(in_array($mode, ['plan', 'migrate', 'verify'], true), 'Invalid --mode. Use plan, migrate or verify.');
check(str_starts_with($socket, '/'), 'Expected absolute local MariaDB socket.');
$qaDelay = (int) ($opt['qa-lock-delay-ms'] ?? 0);
check($qaDelay >= 0 && $qaDelay <= 3000, 'Invalid QA lock delay.');
check($qaDelay === 0 || (str_starts_with($source, 'achgw_qa_') && str_starts_with($dest, 'achgw_qa_')),
    'QA lock delay is only supported on disposable achgw_qa_* schemas.');
if ($mode === 'migrate') {
    check(array_key_exists('ack-source-quiesced', $opt)
        && array_key_exists('ack-destination-scheduler-paused', $opt),
        'Migration requires confirmed source write freeze and suspended destination scheduler.');
}

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
$locker = null;
$sourceLocked = false;
$failed = false;
try {
    validateTableEngines($pdo, $source, $dest, $copyOrder);
    if ($mode !== 'plan') {
        // A separate session owns all legacy READ locks. Starting the
        // destination transaction on the lock-owning session would drop them.
        $locker = new PDO('mysql:unix_socket='.$socket.';charset=utf8mb4', 'root', '', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_PERSISTENT => false,
        ]);
        $locker->exec('SET SESSION lock_wait_timeout=20');
        $sourceTables = rows($pdo, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='
            .$pdo->quote($source)." AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME");
        check($sourceTables !== [], 'Source has no tables.');
        $locker->exec('LOCK TABLES '.implode(',', array_map(
            fn ($entry) => tableName($source, (string) $entry['TABLE_NAME']).' READ',
            $sourceTables
        )));
        $sourceLocked = true;
        echo "SOURCE_WRITE_LOCK=ACQUIRED\n";
        if ($qaDelay > 0) {
            usleep($qaDelay * 1000);
        }
    }
    $pdo->beginTransaction();
    sameOwner($pdo, $source, $dest);
    $srcTables = rows($pdo, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='.$pdo->quote($source).' ORDER BY TABLE_NAME');
    $actual = array_column($srcTables, 'TABLE_NAME');
    $unknown = array_diff($actual, array_merge($copyOrder, $exclude));
    check($unknown === [], 'Unclassified source tables: '.implode(',', $unknown));
    $notPresent = array_diff($copyOrder, $actual);
    check($notPresent === [], 'Required source tables missing: '.implode(',', $notPresent));
    $originalOwnerPassword = (string) $pdo->query('SELECT password FROM '.tableName($dest, 'users').' WHERE role = '.$pdo->quote('owner'))->fetchColumn();
    assertDestinationAccess($pdo, $dest);
    assertNoExistingRuntime($pdo, $dest);

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
        // Only exact previously imported rows are allowed to survive retries.
        foreach ($tablesToCheck as $table => [$cols, $where]) {
            if ($table === 'operational_settings') {
                continue;
            }
            check(destinationExtra($pdo, $source, $dest, $table) === 0,
                'Destination contains unrelated records: '.$table);
            check(destinationConflict($pdo, $source, $dest, $table, $cols) === 0,
                'Destination contains conflicting records: '.$table);
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
            if ($table !== 'operational_settings') {
                check(destinationExtra($pdo, $source, $dest, $table) === 0,
                    'Destination extra records after migration: '.$table);
            }
            echo "verified=$table mismatches=0\n";
        }
        $newOwnerPassword = (string) $pdo->query('SELECT password FROM '.tableName($dest, 'users').' WHERE role = '.$pdo->quote('owner'))->fetchColumn();
        check(hash_equals($originalOwnerPassword, $newOwnerPassword), 'Fresh v3 Owner password unexpectedly modified.');
        assertDestinationAccess($pdo, $dest);
        assertNoExistingRuntime($pdo, $dest);
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
    fwrite(STDERR, 'RESULT=FAILED '.get_class($e).' '.$e->getMessage()."\n");
    $failed = true;
} finally {
    if ($sourceLocked) {
        try {
            $locker->exec('UNLOCK TABLES');
        } catch (Throwable) {
            fwrite(STDERR, "WARNING=SOURCE_LOCK_RELEASE_UNCONFIRMED\n");
        }
    }
}
if ($failed) {
    exit(1);
}
