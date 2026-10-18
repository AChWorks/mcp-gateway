<?php

namespace App\Application\Mcp;

use App\Application\Files\ChatGptFileIngress;
use App\Application\Operations\OperationalSettings;
use App\Infrastructure\Http\OutboundRequestException;
use App\Models\User;
use Throwable;

/**
 * Stage a host-provided file under the existing authorized WordPress lease.
 *
 * This entrypoint deliberately CANNOT publish Media. Retrying this tool after
 * losing its response may allocate another expiring private lease, but cannot
 * create a second WordPress native effect. Publication is a separate explicit
 * provider operation using the stable, originally returned transfer_id.
 */
final readonly class WordpressFileInputMcpToolHandlers
{
    public function __construct(
        private WordpressTargetMcpToolHandlers $wordpress,
        private ChatGptFileIngress $ingress,
        private OperationalSettings $settings,
    ) {}

    /**
     * @param  array<string, mixed>  $file  Host-supplied file parameter.
     * @return array<string, mixed>
     */
    public function receive(User $user, string $target_id, array $file): array
    {
        if (! self::validFile($file)) {
            return self::failed('invalid_file_input', 'A supported ChatGPT file parameter is required.');
        }
        $filename = $file['file_name'] ?? null;
        if ($filename !== null && (! is_string($filename) || ! self::validFilename($filename))) {
            return self::failed('invalid_filename', 'The supplied Media filename is not valid.');
        }

        // The dynamic WordPress private-transfer tool is destructive-class.
        // Its limits probe checks the exact Gateway Target/execution grant,
        // but does NOT prove purpose-specific WordPress permissions.
        $limits = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', ['action' => 'limits']);
        if (($limits['ok'] ?? false) !== true || ! is_array($limits['result'] ?? null)) {
            return self::downstream('limits', $limits, null);
        }
        $budget = $limits['result']['max_chunk_bytes'] ?? null;
        if (! is_int($budget) || $budget < 1) {
            return self::failed('provider_contract_unavailable', 'The WordPress private transfer size contract is unavailable.');
        }

        // Bridge's actual begin(media) guard is Builder Write + upload_files.
        // Inspect BOTH authoritative non-effectful provider projections before
        // even fetching a signed private file. These are individually
        // authenticated, current-user/Target-scoped and readonly-class. If Site
        // Read or the readonly Gateway grant is unavailable, fail closed.
        $groups = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/bridge-info', []);
        if (($groups['ok'] ?? false) !== true || ! is_array($groups['result'] ?? null)) {
            return self::downstream('media_group_preflight', $groups, null);
        }
        if (($groups['result']['access_groups']['builder_write'] ?? null) !== true) {
            return self::failed('media_permission_denied', 'Builder Write is not enabled for the selected WordPress Target.');
        }
        $principal = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/site-context', [
            'section' => 'current_user',
        ]);
        if (($principal['ok'] ?? false) !== true || ! is_array($principal['result'] ?? null)) {
            return self::downstream('media_principal_preflight', $principal, null);
        }
        if (! is_int($principal['result']['current_user']['id'] ?? null)
            || $principal['result']['current_user']['id'] < 1
            || ($principal['result']['current_user']['capabilities']['upload_files'] ?? null) !== true) {
            return self::failed('media_permission_denied', 'The authenticated WordPress principal cannot upload Media.');
        }

        // The owner-configurable WordPress mode budget is separate from the
        // SSH whole-file profile and the shared 8-MiB JSON response ceiling.
        $budget = $this->settings->chatgptWordpressFileLimits();
        $deadline = hrtime(true) + $budget['max_seconds'] * 1_000_000_000;
        try {
            $download = $this->ingress->download($file, $budget['max_bytes'], $budget['max_seconds']);
        } catch (OutboundRequestException $exception) {
            return self::failed($exception->reason, 'The private ChatGPT file could not be retrieved safely.');
        } catch (Throwable) {
            return self::failed('file_download_unavailable', 'The private ChatGPT file could not be retrieved safely.');
        }

        $stream = $download['stream'];
        try {
            return $this->stage($user, $target_id, $stream, $download['bytes'],
                $download['sha256'], $deadline);
        } finally {
            fclose($stream);
        }
    }

    /**
     * @param  resource  $stream
     * @return array<string,mixed>
     */
    private function stage(User $user, string $target_id, mixed $stream, int $bytes,
        string $sha256, int $deadline): array
    {
        if (hrtime(true) >= $deadline) {
            return self::failed('file_transfer_timed_out', 'The file-input transfer exceeded its deadline.');
        }
        $begin = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', [
            'action' => 'begin', 'purpose' => 'media', 'total_bytes' => $bytes, 'sha256' => $sha256,
        ]);
        if (($begin['ok'] ?? false) !== true || ! is_array($begin['result'] ?? null)) {
            return self::downstream('begin', $begin, null);
        }
        $receipt = $begin['result'];
        $transferId = $receipt['transfer_id'] ?? null;
        if (! is_string($transferId) || preg_match('/^[0-9a-f]{64}$/D', $transferId) !== 1) {
            // An allocation may have succeeded even if the receipt is broken.
            // Never repeat an uncertain provider admission automatically.
            return self::failed('transfer_receipt_unknown', 'A private transfer may exist; do not retry automatically.');
        }
        if (($receipt['action'] ?? null) !== 'begin'
            || ($receipt['purpose'] ?? null) !== 'media'
            || ($receipt['state'] ?? null) !== 'open'
            || ($receipt['total_bytes'] ?? null) !== $bytes
            || ($receipt['received_bytes'] ?? null) !== 0
            || ($receipt['sha256'] ?? null) !== $sha256) {
            return self::failed('transfer_receipt_unknown', 'The allocated private transfer identity did not match.', $transferId);
        }
        $providerChunk = $receipt['max_chunk_bytes'] ?? null;
        if (! is_int($providerChunk) || $providerChunk < 1) {
            return self::failed('provider_contract_unavailable', 'The provider chunk budget is invalid.', $transferId);
        }
        $chunk = min($providerChunk, 49152);
        for ($offset = 0; $offset < $bytes;) {
            if (hrtime(true) >= $deadline) {
                return self::failed('file_transfer_timed_out', 'The file-input transfer exceeded its deadline.', $transferId);
            }
            $part = fread($stream, min($chunk, $bytes - $offset));
            if (! is_string($part) || $part === '') {
                return self::failed('file_staging_unavailable', 'The private staged file changed.', $transferId);
            }
            $append = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', [
                'action' => 'append', 'transfer_id' => $transferId, 'offset' => $offset,
                'content_base64' => base64_encode($part),
            ]);
            if (($append['ok'] ?? false) !== true) {
                return self::downstream('append', $append, $transferId);
            }
            $observed = $append['result'] ?? null;
            if (! is_array($observed)
                || ($observed['action'] ?? null) !== 'append'
                || ($observed['transfer_id'] ?? null) !== $transferId
                || ($observed['purpose'] ?? null) !== 'media'
                || ($observed['state'] ?? null) !== 'open'
                || ($observed['total_bytes'] ?? null) !== $bytes
                || ($observed['sha256'] ?? null) !== $sha256
                || ($observed['received_bytes'] ?? null) !== ($offset + strlen($part))) {
                return self::failed('transfer_progress_unknown', 'The transfer progress receipt did not match.', $transferId);
            }
            $offset += strlen($part);
        }
        if (hrtime(true) >= $deadline) {
            return self::failed('file_transfer_timed_out', 'The file-input transfer exceeded its deadline.', $transferId);
        }
        $verify = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', [
            'action' => 'verify', 'transfer_id' => $transferId,
        ]);
        if (($verify['ok'] ?? false) !== true) {
            return self::downstream('verify', $verify, $transferId);
        }
        if (hrtime(true) >= $deadline) {
            return self::failed('file_transfer_timed_out', 'The file-input transfer exceeded its deadline.', $transferId);
        }
        $verified = $verify['result'] ?? null;
        if (! is_array($verified)
            || ($verified['action'] ?? null) !== 'verify'
            || ($verified['transfer_id'] ?? null) !== $transferId
            || ($verified['purpose'] ?? null) !== 'media'
            || ($verified['state'] ?? null) !== 'verified'
            || ($verified['complete'] ?? null) !== true
            || ($verified['received_bytes'] ?? null) !== $bytes
            || ($verified['total_bytes'] ?? null) !== $bytes
            || ($verified['sha256'] ?? null) !== $sha256) {
            return self::failed('transfer_integrity_unknown', 'The WordPress transfer integrity receipt did not match.', $transferId);
        }

        return [
            'ok' => true, 'state' => 'verified_private_transfer', 'target_id' => $target_id,
            'transfer_id' => $transferId, 'bytes' => $bytes, 'sha256' => $sha256,
            'next_step' => 'Only after this receipt is received: explicitly call wp-ai-bridge/transfer-media-import with the same transfer_id and an authorized filename. Never retry an uncertain native import with a new transfer.',
        ];
    }

    /** @param array<string,mixed> $file */
    public static function validFile(array $file): bool
    {
        return ChatGptFileIngress::validFile($file);
    }

    public static function validFilename(string $filename): bool
    {
        return strlen($filename) <= 255 && $filename !== ''
            && preg_match('//u', $filename) === 1
            && strpbrk($filename, '/\\') === false
            && preg_match('/[\x00-\x1F\x7F]/', $filename) !== 1
            && str_contains($filename, '.');
    }

    /** @return array<string,mixed> */
    private static function failed(string $code, string $message, ?string $transferId = null): array
    {
        return ['ok' => false, 'error' => [
            'code' => $code, 'message' => $message, 'retry_safe' => false,
            ...($transferId !== null ? ['transfer_id' => $transferId] : []),
        ]];
    }

    /** @param array<string,mixed> $downstream
     * @return array<string,mixed>
     */
    private static function downstream(string $phase, array $downstream, ?string $transferId): array
    {
        $error = $downstream['error'] ?? null;

        return ['ok' => false, 'error' => [
            'code' => is_array($error) && is_string($error['code'] ?? null) ? $error['code'] : 'downstream_unavailable',
            'message' => 'The WordPress transfer stage did not complete successfully.',
            'phase' => $phase, 'retry_safe' => false,
            ...(is_array($error) && isset($error['diagnostic_reference']) ? ['diagnostic_reference' => $error['diagnostic_reference']] : []),
            ...($transferId !== null ? ['transfer_id' => $transferId] : []),
        ]];
    }
}
