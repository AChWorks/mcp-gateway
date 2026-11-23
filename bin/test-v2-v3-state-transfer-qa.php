<?php

declare(strict_types=1);

/**
 * Destructive synthetic-fixture QA for the v2->v3 operator transfer.
 * Run only on prepared disposable achgw_qa_* MariaDB schemas.
 * The destination must already contain one completed synthetic import.
 * Nothing in this test makes a provider request or changes a live Gateway.
 */
$opt = getopt('', ['source:', 'destination:', 'socket:']);
$source = (string) ($opt['source'] ?? '');
$dest = (string) ($opt['destination'] ?? '');
$socket = (string) ($opt['socket'] ?? '');
foreach ([$source, $dest] as $name) {
    if (preg_match('/^achgw_qa_[a-z0-9_]+$/D', $name) !== 1) {
        throw new RuntimeException('QA script only supports achgw_qa_* schemas.');
    }
}
if ($source === $dest || ! str_starts_with($socket, '/')) {
    throw new RuntimeException('Distinct QA schemas and absolute socket are required.');
}
$db = new PDO('mysql:unix_socket='.$socket.';charset=utf8mb4', 'root', '', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

function assertQa(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException('QA assertion failed: '.$message);
    }
}

function q(string $name): string
{
    return chr(96).$name.chr(96);
}

function countQa(PDO $db, string $schema, string $table): int
{
    return (int) $db->query('SELECT COUNT(*) FROM '.q($schema).'.'.q($table))->fetchColumn();
}

/**
 * @param  list<string>  $additional
 * @return array{int,string,string}
 */
function runTransfer(string $source, string $dest, string $socket, string $mode, array $additional = []): array
{
    $args = [
        PHP_BINARY, __DIR__.'/migrate-v2-to-v3-state.php',
        '--source='.$source, '--destination='.$dest, '--socket='.$socket,
        '--mode='.$mode,
        ...($mode === 'migrate' ? ['--ack-source-quiesced', '--ack-destination-scheduler-paused'] : []),
        ...$additional,
    ];
    $process = proc_open($args, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (! is_resource($process)) {
        throw new RuntimeException('Could not start migration candidate.');
    }
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($process), (string) $stdout, (string) $stderr];
}

function checkRun(string $label, string $source, string $dest, string $socket, string $mode, bool $success, string $errorPart = ''): void
{
    [$exit, $out, $err] = runTransfer($source, $dest, $socket, $mode);
    assertQa(($exit === 0) === $success, $label.' unexpected exit code '.$exit.' error='.substr($err, 0, 220));
    if ($success && $mode === 'migrate') {
        assertQa(str_contains($out, 'RESULT=TRANSFER_COMMITTED'), $label.' did not commit');
    }
    if ($errorPart !== '') {
        assertQa(str_contains($err, $errorPart), $label.' wrong failure: '.substr($err, 0, 220));
    }
    echo "PASS=$label\n";
}

// Only this QA-owned synthetic delta ID is safe to reset between test runs.
$driftId = '01J00000000000000000000019';
$srcDrift = (int) $db->query('SELECT COUNT(*) FROM '.q($source).".activity_events WHERE id='".$driftId."'")->fetchColumn();
$dstDrift = (int) $db->query('SELECT COUNT(*) FROM '.q($dest).".activity_events WHERE id='".$driftId."'")->fetchColumn();
assertQa($srcDrift === $dstDrift, 'Previous QA drift test did not reconcile; inspect before reuse.');
foreach ([$source, $dest] as $schema) {
    $db->exec('DELETE FROM '.q($schema).".activity_events WHERE id='".$driftId."'");
}
$ownerHash = (string) $db->query('SELECT password FROM '.q($dest).'.users WHERE id=1')->fetchColumn();
assertQa(countQa($db, $dest, 'users') === 2 && countQa($db, $dest, 'targets') === 3, 'Synthetic fixture not already imported.');
assertQa(countQa($db, $source, 'target_credentials') === 3, 'Incomplete synthetic credential set.');
assertQa(countQa($db, $source, 'ssh_command_jobs') === 1, 'Missing excluded old SSH Job fixture.');
assertQa(countQa($db, $source, 'oauth_authorizations') === 1
    && countQa($db, $source, 'oauth_access_tokens') === 1
    && countQa($db, $source, 'oauth_refresh_tokens') === 1, 'Missing excluded old ChatGPT OAuth fixtures.');
assertQa(countQa($db, $dest, 'migrations') === 2, 'Destination v3 migrations mismatch.');

checkRun('plan', $source, $dest, $socket, 'plan', true);
checkRun('verify_initial', $source, $dest, $socket, 'verify', true);
[$exit, $out] = runTransfer($source, $dest, $socket, 'migrate');
assertQa($exit === 0 && str_contains($out, 'RESULT=TRANSFER_COMMITTED')
    && preg_match('/inserted=[^\r\n]+ rows=[1-9]/', $out) !== 1,
    'Repeated migration inserted duplicate rows.');
echo "PASS=idempotence\n";

try {
    $db->exec('UPDATE '.q($dest).'.users SET self_created_target_access=1 WHERE id=2');
    checkRun('admin_creator_scope_rejected', $source, $dest, $socket, 'migrate', false, 'creator-scope');
} finally {
    $db->exec('UPDATE '.q($dest).'.users SET self_created_target_access=0 WHERE id=2');
}

try {
    $db->exec('INSERT INTO '.q($dest).".users (id,name,email,password,role,target_scope_mode) VALUES (3,'QA Extra','extra@qa.test','hash','viewer','selected')");
    checkRun('extra_destination_user_rejected', $source, $dest, $socket, 'migrate', false, 'unrelated records: users');
} finally {
    $db->exec('DELETE FROM '.q($dest).'.users WHERE id=3');
}

try {
    $db->exec('INSERT INTO '.q($dest).".target_groups (id,name) VALUES ('01J00000000000000000000014','QA Unrelated')");
    checkRun('extra_group_rejected', $source, $dest, $socket, 'migrate', false, 'unrelated records: target_groups');
} finally {
    $db->exec('DELETE FROM '.q($dest).".target_groups WHERE name='QA Unrelated'");
}

try {
    $db->exec('INSERT INTO '.q($dest).".user_permission_denials (id,user_id,permission) VALUES (3,2,'targets.update')");
    checkRun('extra_destination_deny_rejected', $source, $dest, $socket, 'migrate', false, 'unrelated records: user_permission_denials');
} finally {
    $db->exec('DELETE FROM '.q($dest).'.user_permission_denials WHERE id=3');
}

try {
    $db->exec('UPDATE '.q($dest).".activity_events SET target_id=CONCAT(target_id,' ') WHERE id='01J00000000000000000000013'");
    checkRun('trailing_space_byte_exact', $source, $dest, $socket, 'verify', false, 'Data fidelity mismatch');
} finally {
    $db->exec('UPDATE '.q($dest).'.activity_events d JOIN '.q($source).'.activity_events s ON d.id=s.id SET d.target_id=s.target_id');
}

try {
    $db->exec('UPDATE '.q($dest).".activity_events SET target_id='QA-SSH' WHERE id='01J00000000000000000000013'");
    checkRun('case_byte_exact', $source, $dest, $socket, 'verify', false, 'Data fidelity mismatch');
} finally {
    $db->exec('UPDATE '.q($dest).'.activity_events d JOIN '.q($source).'.activity_events s ON d.id=s.id SET d.target_id=s.target_id');
}

try {
    $db->exec('UPDATE '.q($dest).".target_credentials SET encrypted_payload=CONCAT(LEFT(encrypted_payload,CHAR_LENGTH(encrypted_payload)-1),'Z') WHERE id='01J00000000000000000000006'");
    checkRun('ciphertext_last_byte', $source, $dest, $socket, 'verify', false, 'Data fidelity mismatch');
} finally {
    $db->exec('UPDATE '.q($dest).'.target_credentials d JOIN '.q($source).'.target_credentials s ON d.id=s.id SET d.encrypted_payload=s.encrypted_payload');
}

try {
    $db->exec('UPDATE '.q($dest).".ssh_direct_target_configs SET pinned_host_key=CONCAT(pinned_host_key,'X') WHERE target_record_id='01J00000000000000000000002'");
    checkRun('host_pin_last_byte', $source, $dest, $socket, 'verify', false, 'Data fidelity mismatch');
} finally {
    $db->exec('UPDATE '.q($dest).'.ssh_direct_target_configs d JOIN '.q($source).'.ssh_direct_target_configs s ON d.id=s.id SET d.pinned_host_key=s.pinned_host_key');
}

try {
    $db->exec('UPDATE '.q($dest).".activity_events SET id='01j00000000000000000000013' WHERE id='01J00000000000000000000013'");
    checkRun('case_sensitive_primary_key', $source, $dest, $socket, 'verify', false, 'Data fidelity mismatch');
} finally {
    $db->exec('UPDATE '.q($dest).".activity_events SET id='01J00000000000000000000013' WHERE id='01j00000000000000000000013'");
}

try {
    $db->exec('INSERT INTO '.q($source).".wp_ai_bridge_oauth_flows (id,target_record_id,state_hash,encrypted_context,expires_at) VALUES ('01J00000000000000000000017','01J00000000000000000000003',REPEAT('a',64),'qa-inflight','2035-01-01 00:00:00')");
    checkRun('inflight_source_rejected', $source, $dest, $socket, 'migrate', false, 'Outstanding non-ChatGPT');
} finally {
    $db->exec('DELETE FROM '.q($source).".wp_ai_bridge_oauth_flows WHERE id='01J00000000000000000000017'");
}

try {
    $db->exec('INSERT INTO '.q($source).".target_groups (id,name) VALUES ('01J00000000000000000000018','QA Rollback Group')");
    $db->exec('SET FOREIGN_KEY_CHECKS=0');
    $db->exec('INSERT INTO '.q($source).".user_permission_denials (id,user_id,permission) VALUES (44,999,'unbound.test')");
    $db->exec('SET FOREIGN_KEY_CHECKS=1');
    checkRun('foreign_key_failure_rolled_back', $source, $dest, $socket, 'migrate', false);
    assertQa((int) $db->query('SELECT COUNT(*) FROM '.q($dest).".target_groups WHERE name='QA Rollback Group'")->fetchColumn() === 0,
        'Mid-import FK failure leaked already-inserted group.');
    echo "PASS=atomic_rollback\n";
} finally {
    $db->exec('SET FOREIGN_KEY_CHECKS=0');
    $db->exec('DELETE FROM '.q($source).'.user_permission_denials WHERE id=44');
    $db->exec('SET FOREIGN_KEY_CHECKS=1');
    $db->exec('DELETE FROM '.q($source).".target_groups WHERE name='QA Rollback Group'");
}

try {
    $db->exec('ALTER TABLE '.q($dest).'.activity_events ENGINE=MyISAM');
    checkRun('non_innodb_rejected', $source, $dest, $socket, 'migrate', false, 'transactional InnoDB');
} finally {
    $db->exec('ALTER TABLE '.q($dest).'.activity_events ENGINE=InnoDB');
}

try {
    $db->exec('INSERT INTO '.q($source).".activity_events (id,correlation_id,actor_type,operation,outcome,created_at) VALUES ('01J00000000000000000000019','00000000-0000-4000-8000-000000000019','qa','source.delta','completed','2025-01-01 00:00:00')");
    checkRun('source_drift_detected', $source, $dest, $socket, 'verify', false, 'Data fidelity mismatch');
    checkRun('reconciled_source_delta', $source, $dest, $socket, 'migrate', true);
    checkRun('verify_after_reconciliation', $source, $dest, $socket, 'verify', true);
} finally {
    // Restore the exact synthetic baseline for safe repeated QA.
    foreach ([$source, $dest] as $schema) {
        $db->exec('DELETE FROM '.q($schema).".activity_events WHERE id='01J00000000000000000000019'");
    }
}

// Verify that a real writer cannot change legacy state while the helper
// holds its source-table READ fence and destination transaction.
$lockCommand = [
    PHP_BINARY, __DIR__.'/migrate-v2-to-v3-state.php',
    '--source='.$source, '--destination='.$dest, '--socket='.$socket,
    '--mode=migrate', '--ack-source-quiesced', '--ack-destination-scheduler-paused',
    '--qa-lock-delay-ms=3000',
];
$lockingProcess = proc_open($lockCommand, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $lockingPipes);
assertQa(is_resource($lockingProcess), 'Could not launch source-lock concurrency test.');
stream_set_blocking($lockingPipes[1], false);
$seenLock = false;
$lockOut = '';
try {
    for ($i = 0; $i < 50; $i++) {
        $lockOut .= (string) stream_get_contents($lockingPipes[1]);
        if (str_contains($lockOut, 'SOURCE_WRITE_LOCK=ACQUIRED')) {
            $seenLock = true;
            break;
        }
        usleep(20000);
    }
    assertQa($seenLock, 'Source lock was not acquired by QA migration.');
    $writer = new PDO('mysql:unix_socket='.$socket.';charset=utf8mb4', 'root', '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $writer->exec('SET SESSION lock_wait_timeout=1');
    $rejectedWriter = false;
    try {
        $writer->exec('UPDATE '.q($source).'.operational_settings SET version=version+1 WHERE id=1');
    } catch (PDOException $e) {
        $rejectedWriter = (string) $e->errorInfo[1] === '1205';
    }
    assertQa($rejectedWriter, 'A concurrent legacy writer was not blocked by source READ locks.');
} finally {
    stream_set_blocking($lockingPipes[1], true);
    $lockOut .= (string) stream_get_contents($lockingPipes[1]);
    fclose($lockingPipes[1]);
    $lockErr = (string) stream_get_contents($lockingPipes[2]);
    fclose($lockingPipes[2]);
    $lockExit = proc_close($lockingProcess);
}
assertQa($lockExit === 0 && str_contains($lockOut, 'RESULT=TRANSFER_COMMITTED'),
    'Lock-holding migration did not complete: '.substr($lockErr, 0, 250));
echo "PASS=source_write_blocked_during_transaction\n";
checkRun('post_lock_fidelity', $source, $dest, $socket, 'verify', true);

assertQa(hash_equals($ownerHash, (string) $db->query('SELECT password FROM '.q($dest).'.users WHERE id=1')->fetchColumn()),
    'Destination fresh Owner password changed.');
assertQa(countQa($db, $dest, 'ssh_command_jobs') === 0
    && countQa($db, $dest, 'oauth_authorizations') === 0
    && countQa($db, $dest, 'oauth_access_tokens') === 0
    && countQa($db, $dest, 'oauth_refresh_tokens') === 0, 'Excluded runtime state appeared.');
assertQa((int) $db->query('SELECT COUNT(*) FROM '.q($dest).'.wp_ai_bridge_credential_metadata WHERE refresh_due_at < NOW()')->fetchColumn() === 1,
    'Due WordPress metadata was not retained for controlled activation.');

echo "RESULT=QA_CONTRACT_PASS\n";
