<?php

declare(strict_types=1);

use Mcp\Client;

/** Identical staged-script workload and assertions across actual SSH routes. */
function qualifyStagedScript(Closure $run, Closure $check, int $sleepSeconds = 0): array
{
    // Same admitted byte ceiling, explicitly staged instead of native argv.
    $tail = "\n".($sleepSeconds > 0 ? 'sleep '.$sleepSeconds."\n" : '')
        .'printf "staged-512k-ok"; printf "staged-512k-err" >&2; exit 7';
    $script = '# '.str_repeat('x', 524288 - 2 - strlen($tail)).$tail;
    $staged = $run($script, '/bin/sh');
    $stageResult = $staged['result'] ?? [];
    $check(($staged['ok'] ?? false) === true && ($stageResult['status'] ?? null) === 'completed'
        && ($stageResult['complete'] ?? false) === true
        && ($stageResult['script_bytes'] ?? null) === 524288
        && ($stageResult['script_staging_verified'] ?? false) === true
        && ($stageResult['script_launch_attempted'] ?? false) === true
        && ($stageResult['stdout'] ?? null) === 'staged-512k-ok'
        && ($stageResult['stderr'] ?? null) === 'staged-512k-err'
        && ($stageResult['exit_code'] ?? null) === 7
        && ($stageResult['temporary_cleanup_confirmed'] ?? false) === true
        && ($stageResult['duration_ms'] ?? 0) >= $sleepSeconds * 1000,
        'Verified 512 KiB staged synchronous script failed: '.json_encode($staged, JSON_THROW_ON_ERROR));
    $stageEvidence = [
        'input_bytes' => strlen($script), 'interpreter' => '/bin/sh',
        'script_staging_verified' => $stageResult['script_staging_verified'],
        'script_launch_attempted' => $stageResult['script_launch_attempted'],
        'stdout' => $stageResult['stdout'], 'stderr' => $stageResult['stderr'],
        'exit_code' => $stageResult['exit_code'], 'temporary_cleanup_confirmed' => $stageResult['temporary_cleanup_confirmed'],
        'duration_ms' => $stageResult['duration_ms'],
    ];

    return $stageEvidence;
}

function qualifyInstalledStagedScript(
    Client $client, string $target, string $prefix, Closure $call, Closure $check,
    int $sleepSeconds = 0, int $timeout = 0,
): array {
    $label = $prefix.'ssh_staged_512k'.($sleepSeconds > 0 ? '_'.$sleepSeconds.'s' : '');
    if ($sleepSeconds > 0) {
        $check($timeout > $sleepSeconds, 'Extended staged fixture requires time for preparation and cleanup.');
        fwrite(STDERR, 'Stage: '.$label.' with selected '.$timeout."s timeout.\n");
    }
    $started = hrtime(true);
    $result = qualifyStagedScript(
        static fn (string $script, string $interpreter): array => $call($client, 'ssh-script-run', [
            'target_id' => $target, 'script' => $script, 'interpreter' => $interpreter,
            ...($timeout > 0 ? ['timeout_seconds' => $timeout] : []),
        ], $label, $timeout > 0 ? $timeout + 30 : null),
        $check,
        $sleepSeconds,
    );
    if ($sleepSeconds > 0) {
        $clientMs = round((hrtime(true) - $started) / 1000000, 2);
        $check($clientMs >= $sleepSeconds * 1000, 'Extended staged SDK duration is shorter than the actual workload.');
        $result += [
            'requested_sleep_seconds' => $sleepSeconds, 'selected_timeout_seconds' => $timeout,
            'client_duration_ms' => $clientMs,
        ];
    }

    return $result;
}

function qualifyInstalledInlineSftp(Client $client, string $target, string $prefix, Closure $call, Closure $check): array
{
    $bytes = random_bytes(524288);
    $account = (string) getenv('MIXED_SSH_USER');
    $check(preg_match('/^mcpac[0-9]+$/D', $account) === 1, 'Expected the disposable SSH account.');
    $file = '/home/'.$account.'/mixed-'.bin2hex(random_bytes(8)).'.bin';
    try {
        $write = $call($client, 'ssh-file-write', [
            'target_id' => $target, 'path' => $file, 'content_base64' => base64_encode($bytes)], $prefix.'sftp_write');
        $check(($write['ok'] ?? false) === true && ($write['result']['bytes_written'] ?? null) === strlen($bytes)
            && ($write['result']['integrity_check'] ?? null) === 'remote_readback_sha256', 'Binary write integrity/count wrong.');
        $stat = $call($client, 'ssh-file-stat', [
            'target_id' => $target, 'path' => $file], $prefix.'sftp_stat');
        $check(($stat['result']['file']['size'] ?? null) === strlen($bytes), 'Binary stat size wrong.');
        $read = $call($client, 'ssh-file-read', [
            'target_id' => $target, 'path' => $file, 'length' => strlen($bytes)], $prefix.'sftp_read');
        $back = base64_decode($read['result']['data'] ?? '', true);
        $check(($read['ok'] ?? false) === true && is_string($back) && ($read['result']['end_of_file'] ?? false) === true && hash_equals($bytes, $back)
            && hash_equals(hash('sha256', $bytes), hash('sha256', $back)), 'Binary SFTP roundtrip wrong.');
    } finally {
        $cleanup = $call($client, 'ssh-command-run', [
            'target_id' => $target, 'command' => 'rm -f -- '.escapeshellarg($file).' && test ! -e '.escapeshellarg($file)], $prefix.'sftp_cleanup');
        $check(($cleanup['ok'] ?? false) === true && ($cleanup['result']['exit_code'] ?? null) === 0, 'SFTP disposable payload not removed.');
    }

    return ['bytes' => strlen($bytes), 'sha256' => hash('sha256', $bytes), 'complete' => true];
}
