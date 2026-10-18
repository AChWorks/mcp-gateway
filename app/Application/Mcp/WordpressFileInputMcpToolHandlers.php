<?php

namespace App\Application\Mcp;

use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use App\Models\User;
use Throwable;

/**
 * An optional ChatGPT file-parameter adapter, not a generic URL importer.
 *
 * The existing WordPress authenticated Ability dispatcher owns every user,
 * Target, operation-class and provider permission check. Its private transfer
 * receipts own immutable byte identity, reservations and no-replay claims.
 * Downloaded data are never executed or sent to a destination chosen by URL.
 */
final readonly class WordpressFileInputMcpToolHandlers
{
    // Bounded synchronous host-file fallback, NOT a WordPress/Bridge file-size ceiling.
    public const MAX_INLINE_FILE_BYTES = 262144;

    private const HOST = 'files.oaiusercontent.com';

    public function __construct(
        private WordpressTargetMcpToolHandlers $wordpress,
        private SafeHttpClient $http,
    ) {}

    /**
     * @param  array<string, mixed>  $file  Host-supplied file parameter.
     * @return array<string, mixed>
     */
    public function receive(User $user, string $target_id, array $file, bool $import_to_media = false): array
    {
        if (! self::validFile($file)) {
            return self::failed('invalid_file_input', 'A supported ChatGPT file parameter is required.');
        }
        $filename = $file['file_name'] ?? null;
        if ($import_to_media && (! is_string($filename) || ! self::validFilename($filename))) {
            return self::failed('invalid_filename', 'A single valid file name is required for Media import.');
        }

        // Do not fetch even a trusted ChatGPT file until the exact Gateway
        // WordPress Target and its current Ability execution grant pass.
        $limits = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', ['action' => 'limits']);
        if (($limits['ok'] ?? false) !== true || ! is_array($limits['result'] ?? null)) {
            return self::downstream('limits', $limits, null);
        }
        $budget = $limits['result']['max_chunk_bytes'] ?? null;
        if (! is_int($budget) || $budget < 1) {
            return self::failed('provider_contract_unavailable', 'The WordPress private transfer size contract is unavailable.');
        }

        try {
            $response = $this->http->getChatgptFile($file['download_url'], self::MAX_INLINE_FILE_BYTES);
        } catch (OutboundRequestException $exception) {
            return self::failed($exception->reason, 'The private ChatGPT file could not be retrieved safely.');
        } catch (Throwable) {
            return self::failed('file_download_unavailable', 'The private ChatGPT file could not be retrieved safely.');
        }
        if ($response->status !== 200) {
            return self::failed('file_download_unavailable', 'The private ChatGPT file was not available for download.');
        }

        $bytes = strlen($response->body);
        if ($bytes > self::MAX_INLINE_FILE_BYTES) {
            return self::failed('file_too_large', 'The file exceeds this synchronous ChatGPT file-parameter adapter.');
        }
        if ($import_to_media && $bytes === 0) {
            return self::failed('empty_media', 'WordPress Media Library cannot import an empty file.');
        }
        $sha256 = hash('sha256', $response->body);
        $begin = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', [
            'action' => 'begin', 'purpose' => 'media', 'total_bytes' => $bytes, 'sha256' => $sha256,
        ]);
        if (($begin['ok'] ?? false) !== true || ! is_array($begin['result'] ?? null)) {
            return self::downstream('begin', $begin, null);
        }
        $receipt = $begin['result'];
        $transferId = $receipt['transfer_id'] ?? null;
        if (! is_string($transferId) || preg_match('/^[0-9a-f]{64}$/D', $transferId) !== 1) {
            // A successful remote begin with an invalid receipt is uncertain.
            // Do not repeat it or pretend it did not reserve server bytes.
            return self::failed('transfer_receipt_unknown', 'A private transfer may exist; do not retry automatically.');
        }
        $chunk = min($budget, (int) ($receipt['max_chunk_bytes'] ?? $budget), 49152);
        if ($chunk < 1) {
            return self::failed('provider_contract_unavailable', 'Provider chunk budget is invalid.', $transferId);
        }
        for ($offset = 0; $offset < $bytes; $offset += $chunk) {
            $part = substr($response->body, $offset, $chunk);
            $append = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', [
                'action' => 'append', 'transfer_id' => $transferId, 'offset' => $offset,
                'content_base64' => base64_encode($part),
            ]);
            if (($append['ok'] ?? false) !== true) {
                return self::downstream('append', $append, $transferId);
            }
            $observed = $append['result'] ?? null;
            if (! is_array($observed) || ($observed['received_bytes'] ?? null) !== ($offset + strlen($part))) {
                return self::failed('transfer_progress_unknown', 'The transfer progress acknowledgment did not match.', $transferId);
            }
        }
        $verify = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/private-transfer', [
            'action' => 'verify', 'transfer_id' => $transferId,
        ]);
        if (($verify['ok'] ?? false) !== true) {
            return self::downstream('verify', $verify, $transferId);
        }
        $verified = $verify['result'] ?? null;
        if (! is_array($verified) || ($verified['sha256'] ?? null) !== $sha256
            || ($verified['total_bytes'] ?? null) !== $bytes || ($verified['state'] ?? null) !== 'verified') {
            return self::failed('transfer_integrity_unknown', 'The WordPress transfer integrity result did not match.', $transferId);
        }

        if (! $import_to_media) {
            return [
                'ok' => true, 'state' => 'verified_private_transfer', 'target_id' => $target_id,
                'transfer_id' => $transferId, 'bytes' => $bytes, 'sha256' => $sha256,
                'next_step' => 'Explicitly use wp-ai-bridge/transfer-media-import with this transfer_id and an authorized filename, or cancel this lease.',
            ];
        }

        // An immutable native one-way claim fences the publish effect.
        // Never retry this call after an error or lost outcome.
        $import = $this->wordpress->execute($user, $target_id, 'wp-ai-bridge/transfer-media-import', [
            'transfer_id' => $transferId, 'filename' => $filename,
        ]);
        if (($import['ok'] ?? false) !== true) {
            return self::downstream('media_import', $import, $transferId);
        }
        $destination = $import['result'] ?? null;
        if (! is_array($destination) || ! is_int($destination['media_id'] ?? null)
            || ($destination['sha256'] ?? null) !== $sha256 || ($destination['bytes'] ?? null) !== $bytes) {
            return self::failed('media_import_outcome_unknown', 'WordPress may have created a Media item; reconcile its receipt before any retry.', $transferId);
        }

        return [
            'ok' => true, 'state' => 'imported_media', 'target_id' => $target_id,
            'transfer_id' => $transferId, 'media_id' => $destination['media_id'],
            'bytes' => $bytes, 'sha256' => $sha256,
        ];
    }

    /** @param array<string,mixed> $file */
    public static function validFile(array $file): bool
    {
        $id = $file['file_id'] ?? null;
        $url = $file['download_url'] ?? null;
        if (! is_string($id) || strlen($id) < 1 || strlen($id) > 255
            || ! is_string($url) || strlen($url) < 1 || strlen($url) > 8192
            || ! is_string(parse_url($url, PHP_URL_SCHEME))
            || strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https'
            || strtolower((string) parse_url($url, PHP_URL_HOST)) !== self::HOST
            || parse_url($url, PHP_URL_USER) !== null
            || parse_url($url, PHP_URL_PASS) !== null
            || parse_url($url, PHP_URL_PORT) !== null
            || ! is_string(parse_url($url, PHP_URL_PATH))
            || parse_url($url, PHP_URL_PATH) === '') {
            return false;
        }
        foreach (['mime_type', 'file_name'] as $optional) {
            if (isset($file[$optional]) && (! is_string($file[$optional]) || strlen($file[$optional]) > 255)) {
                return false;
            }
        }

        return true;
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
            'code' => $code, 'message' => $message,
            'retry_safe' => false,
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
            'phase' => $phase,
            'retry_safe' => false,
            ...(is_array($error) && isset($error['diagnostic_reference']) ? ['diagnostic_reference' => $error['diagnostic_reference']] : []),
            ...($transferId !== null ? ['transfer_id' => $transferId] : []),
        ]];
    }
}
