<?php

declare(strict_types=1);

use GuzzleHttp\Client as Http;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;
use Psr\Http\Message\ResponseInterface;

$root = (string) getenv('MIXED_ROOT');
require $root.'/gateway/vendor/autoload.php';
$state = json_decode((string) file_get_contents($root.'/secrets/state.json'), true, 32, JSON_THROW_ON_ERROR);
$http = new Http(['verify' => $root.'/secrets/tls.crt', 'proxy' => '', 'http_errors' => false, 'timeout' => 55]);
$base = 'https://11.22.33.45/mcp/file-transfer/ssh/';
$target = $state['ssh_target'];
$ownerToken = $state['owner_token'];
$sshUser = (string) getenv('MIXED_SSH_USER');
$stage = '/home/'.$sshUser.'/.gateway-transfer-private';
$tests = [];
if (($argv[1] ?? '') === 'revoked') {
    $probe = $http->post($base.rawurlencode($target).'/download', [
        'headers' => ['Authorization' => 'Bearer '.$ownerToken],
        'json' => ['path' => '/home/'.$sshUser.'/cannot-read-after-revocation'],
    ]);
    if ($probe->getStatusCode() !== 401) {
        throw new RuntimeException('Existing revoked Owner bearer accessed binary file edge.');
    }
    echo "PASS previously issued bearer rejected at binary download edge with HTTP 401\n";
    exit(0);
}

$check = static function (bool $success, string $label): void {
    if (! $success) {
        throw new RuntimeException('whole-file installed E2E: '.$label);
    }
};
$client = Client::builder()->setClientInfo('whole-file-php-mcp-sdk', '1.0')
    ->setInitTimeout(8)->setRequestTimeout(30)->setMaxRetries(0)->build();
$client->connect(new HttpTransport(
    endpoint: 'https://11.22.33.45/mcp',
    headers: ['Authorization' => 'Bearer '.$ownerToken],
    httpClient: $http,
));
try {
    $names = array_map(static fn ($tool) => $tool->name, $client->listTools()->tools);
    $check(in_array('ssh-file-stat', $names, true) && in_array('targets-list', $names, true),
        'official MCP SDK did not negotiate Gateway capabilities');
    $listed = $client->callTool('targets-list', ['connector_type' => 'ssh_direct']);
    $ids = array_column(($listed->structuredContent ?? [])['targets'] ?? [], 'target_id');
    $check(in_array($target, $ids, true), 'authorized SSH target not discoverable over real MCP SDK');

    $url = $base.rawurlencode($target);
    $send = static function (string $token, string $path, string $bytes, array $extra = []) use ($http, $url, $stage): ResponseInterface {
        $metadata = [
            'path' => $path, 'private_staging_dir' => $stage,
            'size' => strlen($bytes), 'sha256' => hash('sha256', $bytes), 'overwrite' => false,
            ...$extra,
        ];
        $json = json_encode($metadata, JSON_THROW_ON_ERROR);
        $encoded = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $source = fopen('php://temp/maxmemory:65536', 'w+b');
        fwrite($source, $bytes);
        rewind($source);
        try {
            return $http->post($url.'/upload', [
                'headers' => [
                    'Authorization' => 'Bearer '.$token, 'Content-Type' => 'application/octet-stream',
                    'X-Gateway-Metadata' => $encoded, 'Content-Length' => (string) strlen($bytes),
                ],
                'body' => $source,
            ]);
        } finally {
            // Guzzle may already close the body resource it owns.
            if (is_resource($source)) {
                fclose($source);
            }
        }
    };
    $recv = static function (string $token, string $path, array $extra = []) use ($http, $url): array {
        $sink = fopen('php://temp/maxmemory:65536', 'w+b');
        try {
            $response = $http->post($url.'/download', [
                'headers' => ['Authorization' => 'Bearer '.$token],
                'json' => ['path' => $path, ...$extra],
                'sink' => $sink,
            ]);
            rewind($sink);
            $digest = hash_init('sha256');
            hash_update_stream($digest, $sink);
            $size = fstat($sink)['size'];

            return [
                'status' => $response->getStatusCode(), 'size' => $size,
                'sha256' => hash_final($digest),
                'headers' => [
                    'sha256' => $response->getHeaderLine('X-Gateway-File-SHA256'),
                    'bytes' => $response->getHeaderLine('X-Gateway-File-Bytes'),
                    'type' => $response->getHeaderLine('Content-Type'),
                ],
            ];
        } finally {
            fclose($sink);
        }
    };

    $fixtures = [
        'empty' => '',
        'utf8' => str_repeat("سلام Gateway — 你好 🚀\n", 64),
        'one_kib' => random_bytes(1024),
        'ten_kib' => random_bytes(10240),
        'sixty_four_kib' => random_bytes(65536),
        'two_fifty_six_kib' => random_bytes(262144),
        'binary' => "\x00\xff".random_bytes(1024 * 1024 + 131)."\x7f",
        'png' => base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL/nwAAAABJRU5ErkJggg==', true),
        'pdf' => "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 1\n0000000000 65535 f \ntrailer<</Root 1 0 R>>\n%%EOF\n",
        'zip' => "PK\x05\x06".str_repeat("\x00", 18),
    ];
    $startOverall = hrtime(true);
    foreach ($fixtures as $type => $bytes) {
        $check(is_string($bytes), 'fixture must be binary string: '.$type);
        $path = '/home/'.$sshUser.'/whole-file-'.bin2hex(random_bytes(8)).'-'.$type;
        $begin = hrtime(true);
        $upload = $send($ownerToken, $path, $bytes);
        $body = json_decode((string) $upload->getBody(), true);
        $check($upload->getStatusCode() === 201 && ($body['ok'] ?? false) === true,
            'binary HTTP upload failed for '.$type.' (status='.$upload->getStatusCode().' code='.($body['error']['code'] ?? 'none').')');
        $check(($body['sha256'] ?? null) === hash('sha256', $bytes), 'remote SHA mismatch for '.$type);
        try {
            $stat = ($client->callTool('ssh-file-stat', [
                'target_id' => $target, 'path' => $path,
            ]))->structuredContent;
            $check(($stat['result']['file']['size'] ?? -1) === strlen($bytes),
                'real MCP SDK remote stat mismatch for '.$type);
            if ($type === 'binary') {
                // Create-only retries are not idempotent. A second request must
                // fail without replacing the already verified destination.
                $replay = $send($ownerToken, $path, $bytes);
                $check($replay->getStatusCode() === 409, 'duplicate upload retried and mutated data');
                $changed = $recv($ownerToken, $path, ['expected_sha256' => hash('sha256', 'different-source')]);
                $check($changed['status'] === 409, 'wrong expected remote SHA was accepted');
            }
            $download = $recv($ownerToken, $path, ['expected_sha256' => hash('sha256', $bytes)]);
            $check($download['status'] === 200, 'raw HTTP download failed for '.$type);
            $check($download['size'] === strlen($bytes)
                && hash_equals($download['sha256'], hash('sha256', $bytes))
                && hash_equals($download['headers']['sha256'], hash('sha256', $bytes))
                && (string) strlen($bytes) === $download['headers']['bytes'],
                'client-side whole file SHA/length mismatch for '.$type);
        } finally {
            $clean = ($client->callTool('ssh-command-run', [
                'target_id' => $target, 'command' => 'rm -f -- '.escapeshellarg($path),
            ]))->structuredContent;
            $check($clean['ok'] ?? false, 'cleanup failed');
        }
        $tests[$type] = [
            'size' => strlen($bytes), 'sha256' => hash('sha256', $bytes),
            'roundtrip_ms' => round((hrtime(true) - $begin) / 1e6, 2),
            'client_receiving_mode' => 'HTTP binary bytes captured in client-owned private stream',
        ];
    }

    $notFoundPath = '/home/'.$sshUser.'/missing-'.bin2hex(random_bytes(6));
    $bad = $send('invalid-bearer', $notFoundPath, 'test');
    $check($bad->getStatusCode() === 401, 'invalid bearer upload not rejected');
    $bad = $send($state['disabled_profile_token'], $notFoundPath, 'test');
    $check($bad->getStatusCode() === 401, 'disabled OAuth profile not rejected');
    $bad = $send($state['operator_token'], $notFoundPath, 'test');
    $check($bad->getStatusCode() === 404, 'operator incorrectly allowed into SSH target');
    $bad = $send($ownerToken, '/root/unauthorized-'.bin2hex(random_bytes(6)), 'test');
    $check($bad->getStatusCode() !== 201, 'unauthorized remote destination accepted');
    $bad = $send($ownerToken, $notFoundPath, 'tamper', ['sha256' => str_repeat('0', 64)]);
    $check($bad->getStatusCode() === 422, 'wrong input hash accepted');
    $bad = $recv($ownerToken, $notFoundPath);
    $check($bad['status'] !== 200, 'missing source returned success');
    $bad = $send($ownerToken, $notFoundPath, 'short', ['size' => 4]);
    $check($bad->getStatusCode() === 422, 'declared length mismatch accepted');
    $bad = $send($ownerToken, $notFoundPath, 'hello', ['expected_size' => 0]);
    $check($bad->getStatusCode() === 422, 'unpaired version accepted');
    // Installed Owner override is 4096 KiB: send ACTUAL bytes above it.
    $bad = $send($ownerToken, $notFoundPath, str_repeat('A', 4096 * 1024 + 1));
    $check($bad->getStatusCode() === 413, 'actual over-budget binary upload not rejected');

    echo json_encode([
        'outcome' => 'PASS',
        'direction' => 'authorized external PHP MCP SDK client -> binary HTTP sidecar -> real SFTP Target -> binary HTTP sidecar -> client-owned stream',
        'client_mode' => 'SDK target discovery and stat; OAuth-bound direct binary upload/download on optional sidecar',
        'model_consumed' => false,
        'chatgpt_host_file_handoff' => 'NOT_TESTED',
        'fixtures' => $tests,
        'security_denials' => 'PASS invalid bearer, disabled client, scoped operator, denied destination, bad hash, missing source, wrong length, invalid version, actual oversize, duplicate write, stale source hash',
        'aggregate_ms' => round((hrtime(true) - $startOverall) / 1e6, 2),
        'client_peak_memory_bytes' => memory_get_peak_usage(true),
    ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)."\n";
} finally {
    $client->disconnect();
}
