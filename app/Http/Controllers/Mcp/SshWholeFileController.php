<?php

namespace App\Http\Controllers\Mcp;

use App\Application\Files\SshWholeFileTransfer;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use JsonException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * SOURCE-INTEGRATED, OFF-BY-DEFAULT: OAuth-authenticated SSH whole-file HTTP edge.
 * Public enablement requires actual host/proxy/resource acceptance.
 * Not an MCP resource, nor proof that a ChatGPT host consumes downloaded bytes.
 */
final class SshWholeFileController extends Controller
{
    public function __construct(private readonly SshWholeFileTransfer $files) {}

    public function upload(Request $request, string $targetId): Response
    {
        if (! $this->enabled()) {
            return $this->fail('unsupported_mode', 404);
        }
        try {
            $user = $this->user($request);
            $metadata = $this->uploadMetadata($request);
            // Authorize the exact Target + operation BEFORE reading raw bytes.
            $target = $this->files->target($user, $targetId, GatewayPermission::SshFileWrite);
            $limits = $this->files->limits();
            if ($metadata['size'] > $limits['max_bytes']) {
                throw new SshTargetConnectionException('file_too_large');
            }
            $source = $request->getContent(true);
            if (! is_resource($source)) {
                throw new SshTargetConnectionException('input_unavailable');
            }
            $result = $this->files->upload($user, $target, $metadata['path'], $source, $metadata);
            if (($result['status'] ?? '') === 'outcome_unknown') {
                // Never claim an interrupted post-dispatch write was rolled
                // back. The caller must inspect the Target before retrying.
                return response()->json([
                    'ok' => false,
                    'error' => ['code' => 'outcome_unknown',
                        'message' => 'Remote mutation may have occurred. Inspect the Target before manual retry.'],
                    'possible_remote_effect' => true,
                    'temporary_cleanup_confirmed' => $result['temporary_cleanup_confirmed'] ?? false,
                    'retry_safe' => false,
                ], 409, $this->headers());
            }
            if (($result['status'] ?? '') !== 'completed'
                || ($result['bytes_written'] ?? null) !== $metadata['size']
                || ($result['sha256'] ?? null) !== $metadata['sha256']) {
                return $this->fail('outcome_unknown', 409);
            }

            return response()->json([
                'ok' => true, 'status' => 'completed', 'target_id' => $targetId,
                'path' => $metadata['path'], 'bytes_written' => $result['bytes_written'],
                'sha256' => $result['sha256'], 'integrity_check' => $result['integrity_check'] ?? null,
                'retry_safe' => false,
            ], 201, $this->headers());
        } catch (SshTargetConnectionException $exception) {
            return $this->failure($exception->reason);
        } catch (Throwable) {
            return $this->fail('file_unavailable', 502);
        }
    }

    public function download(Request $request, string $targetId): Response
    {
        if (! $this->enabled()) {
            return $this->fail('unsupported_mode', 404);
        }
        try {
            $user = $this->user($request);
            $metadata = $this->downloadMetadata($request);
            $target = $this->files->target($user, $targetId, GatewayPermission::SshFileRead);
            // Budget covers SFTP + PHP verification + client-side delivery.
            // Host/proxy write deadlines must be independently configured.
            $deadline = hrtime(true) + $this->files->limits()['max_seconds'] * 1_000_000_000;
            $file = $this->files->download($user, $target, $metadata['path'], $metadata);
            $result = $file['identity'];
            $stream = $file['stream'];
            if (hrtime(true) >= $deadline) {
                fclose($stream);
                throw new SshTargetConnectionException('transfer_timed_out');
            }
            $name = basename($metadata['path']);
            $encodedName = rawurlencode($name);
            $headers = [
                ...$this->headers(),
                'Content-Type' => 'application/octet-stream',
                'Content-Length' => (string) $result['bytes_read'],
                'X-Gateway-File-SHA256' => $result['sha256'],
                'X-Gateway-File-Bytes' => (string) $result['bytes_read'],
                'X-Gateway-Target-Id' => $targetId,
                'X-Gateway-Snapshot' => $result['source_check'],
                'Content-Disposition' => 'attachment; filename="file.bin"; filename*=UTF-8\'\''.$encodedName,
            ];

            // A failure before any bytes are returned is an HTTP error.
            // After bytes start, a client disconnect is NOT resumable; client
            // must verify Content-Length and SHA-256 before treating it as a file.
            return response()->stream(static function () use ($stream, $deadline): void {
                try {
                    while (! feof($stream) && ! connection_aborted()) {
                        if (hrtime(true) >= $deadline) {
                            // A partial HTTP 200 body is NOT a completed file.
                            // Clients MUST verify length and SHA-256.
                            break;
                        }
                        $chunk = fread($stream, 65536);
                        if (! is_string($chunk) || $chunk === '') {
                            break;
                        }
                        echo $chunk;
                    }
                } finally {
                    fclose($stream);
                }
            }, 200, $headers);
        } catch (SshTargetConnectionException $exception) {
            return $this->failure($exception->reason);
        } catch (Throwable) {
            return $this->fail('file_unavailable', 502);
        }
    }

    private function enabled(): bool
    {
        return config('ssh.file_transfer.enabled', false) === true;
    }

    private function user(Request $request): User
    {
        $user = $request->attributes->get('oauth_user');
        if (! $user instanceof User || ! $user->access_enabled
            || ! is_string($request->attributes->get('oauth_client_id'))) {
            throw new SshTargetConnectionException('target_not_found');
        }

        return $user;
    }

    /** @return array<string,mixed> */
    private function uploadMetadata(Request $request): array
    {
        if ($request->headers->get('Content-Type') !== 'application/octet-stream'
            || ! in_array($request->headers->get('Content-Encoding', 'identity'), ['identity'], true)) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $header = $request->headers->get('X-Gateway-Metadata');
        if (! is_string($header) || strlen($header) > 4096 || $header === ''
            || preg_match('/^[A-Za-z0-9_-]+$/D', $header) !== 1) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $decoded = base64_decode(strtr($header, '-_', '+/'), true);
        if (! is_string($decoded) || strlen($decoded) > 3072
            || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $header) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $values = $this->json($decoded);
        $this->keys($values, ['path', 'private_staging_dir', 'size', 'sha256', 'overwrite'],
            ['expected_size', 'expected_mtime']);
        if (! is_int($values['size']) || $values['size'] < 0
            || ! is_string($values['sha256'])
            || preg_match('/^[a-f0-9]{64}$/D', $values['sha256']) !== 1
            || ! is_bool($values['overwrite'])
            || ! is_string($values['path']) || ! is_string($values['private_staging_dir'])) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $this->version($values);
        $contentLength = $request->headers->get('Content-Length');
        if (! is_string($contentLength) || ! ctype_digit($contentLength)
            || (string) $values['size'] !== $contentLength) {
            throw new SshTargetConnectionException('input_changed');
        }

        return $values;
    }

    /** @return array<string,mixed> */
    private function downloadMetadata(Request $request): array
    {
        if (! str_starts_with((string) $request->header('Content-Type'), 'application/json')
            || ! in_array($request->headers->get('Content-Encoding', 'identity'), ['identity'], true)) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $length = $request->headers->get('Content-Length');
        if (! is_string($length) || ! ctype_digit($length) || (int) $length > 3072) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $body = $request->getContent();
        if (strlen($body) > 3072 || strlen($body) !== (int) $length) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $values = $this->json($body);
        $this->keys($values, ['path'], ['expected_sha256', 'expected_size', 'expected_mtime']);
        if (! is_string($values['path'])
            || (isset($values['expected_sha256'])
                && (! is_string($values['expected_sha256'])
                    || preg_match('/^[a-f0-9]{64}$/D', $values['expected_sha256']) !== 1))) {
            throw new SshTargetConnectionException('invalid_input');
        }
        $this->version($values);

        return $values;
    }

    /** @return array<string,mixed> */
    private function json(string $body): array
    {
        try {
            $values = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new SshTargetConnectionException('invalid_input');
        }
        if (! is_array($values) || array_is_list($values)) {
            throw new SshTargetConnectionException('invalid_input');
        }

        return $values;
    }

    /**
     * @param  array<string,mixed>  $values
     * @param  list<string>  $required
     * @param  list<string>  $optional
     */
    private function keys(array $values, array $required, array $optional): void
    {
        if (array_diff($required, array_keys($values)) !== []
            || array_diff(array_keys($values), [...$required, ...$optional]) !== []) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    /** @param array<string,mixed> $values */
    private function version(array $values): void
    {
        $size = $values['expected_size'] ?? null;
        $mtime = $values['expected_mtime'] ?? null;
        if (($size === null) !== ($mtime === null)
            || ($size !== null && (! is_int($size) || $size < 0
                || ! is_int($mtime) || $mtime < 0))) {
            throw new SshTargetConnectionException('invalid_input');
        }
    }

    private function failure(string $code): Response
    {
        if ($code === 'file_too_large') {
            // Returned only AFTER successful authorization for an exact Target.
            return response()->json([
                'ok' => false,
                'error' => [
                    'code' => $code,
                    'message' => 'The file exceeds the authorized SSH transfer profile.',
                    'limiting_layer' => 'gateway.ssh.file_transfer',
                    'limit_bytes' => $this->files->limits()['max_bytes'],
                ],
            ], 413, $this->headers());
        }

        return $this->fail($code, match ($code) {
            'target_not_found' => 404,
            'invalid_input', 'input_changed' => 422,
            'source_changed', 'file_exists', 'staging_not_private', 'connection_busy' => 409,
            'rate_limited' => 429,
            'admission_unavailable' => 503,
            'transfer_timed_out' => 504,
            default => 502,
        });
    }

    private function fail(string $code, int $status): JsonResponse
    {
        return response()->json([
            'ok' => false,
            'error' => ['code' => $code, 'message' => 'File exchange could not be completed safely.'],
        ], $status, [...$this->headers(), ...($status === 429 ? ['Retry-After' => '60'] : [])]);
    }

    /** @return array<string,string> */
    private function headers(): array
    {
        return ['Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff'];
    }
}
