<?php

namespace App\Application\Files;

use App\Infrastructure\Http\OutboundRequestException;
use App\Infrastructure\Http\SafeHttpClient;
use Throwable;

/**
 * Source-only, bounded ChatGPT file-param admission shared by all Targets.
 * Never accepts a client-supplied arbitrary URL. The temporary stream is
 * caller-owned and MUST be closed after its single authorized operation.
 */
final readonly class ChatGptFileIngress
{
    public function __construct(
        private SafeHttpClient $http,
        private ChatGptFileCapacity $capacity,
    ) {}

    /** @param array<string,mixed> $file */
    public static function validFile(array $file): bool
    {
        return self::inputValidationClass($file) === null;
    }

    /**
     * Bounded diagnostic classification, without echoing source IDs, URLs,
     * signed queries, file contents or filenames. No outbound side effects.
     *
     * @param  array<string,mixed>  $file
     */
    public static function inputValidationClass(array $file): ?string
    {
        $id = $file['file_id'] ?? null;
        if (! is_string($id) || strlen($id) < 1 || strlen($id) > 255) {
            return 'file_id_invalid';
        }

        $url = $file['download_url'] ?? null;
        if (! is_string($url) || strlen($url) < 1 || strlen($url) > 8192) {
            return 'download_url_invalid';
        }
        if (strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https') {
            return 'download_url_scheme_invalid';
        }
        if (strtolower((string) parse_url($url, PHP_URL_HOST)) !== 'files.oaiusercontent.com') {
            return 'download_url_origin_denied';
        }
        if (parse_url($url, PHP_URL_USER) !== null
            || parse_url($url, PHP_URL_PASS) !== null
            || parse_url($url, PHP_URL_PORT) !== null
            || parse_url($url, PHP_URL_FRAGMENT) !== null) {
            return 'download_url_components_invalid';
        }
        if (! is_string(parse_url($url, PHP_URL_PATH)) || parse_url($url, PHP_URL_PATH) === '') {
            return 'download_url_path_invalid';
        }
        foreach (['mime_type', 'file_name'] as $optional) {
            if (isset($file[$optional]) && (! is_string($file[$optional]) || strlen($file[$optional]) > 255)) {
                return 'file_metadata_invalid';
            }
        }

        return null;
    }

    /**
     * Diagnostic-only sanitized hostname of an origin-denied HTTPS URL.
     * Only a separately Owner-authorized caller may expose the result.
     * Only the DNS hostname is extracted; URL paths/queries, caller file IDs
     * and outbound requests are excluded. Hostnames can themselves be private.
     *
     * @param  array<string,mixed>  $file
     */
    public static function rejectedDownloadHostname(array $file): ?string
    {
        if (self::inputValidationClass($file) !== 'download_url_origin_denied') {
            return null;
        }

        $url = $file['download_url'] ?? null;
        if (! is_string($url) || $url === '' || strlen($url) > 8192
            || preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            return null;
        }

        $parts = parse_url($url);
        if (! is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || ! is_string($parts['path'] ?? null) || $parts['path'] === ''
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['port']) || isset($parts['fragment'])) {
            return null;
        }

        $host = $parts['host'] ?? null;
        if (! is_string($host) || strlen($host) < 4 || strlen($host) > 253) {
            return null;
        }

        $host = strtolower($host);
        if (! str_contains($host, '.') || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return null;
        }
        foreach (explode('.', $host) as $label) {
            if ($label === '' || strlen($label) > 63
                || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/D', $label) !== 1) {
                return null;
            }
        }

        return $host;
    }

    /**
     * @param  array<string,mixed>  $file
     * @return array{stream:resource,bytes:int,sha256:string,capacity_lease:ChatGptFileCapacityLease}
     *
     * @throws OutboundRequestException
     */
    public function download(array $file, int $maxBytes, int $timeoutSeconds, string $mode): array
    {
        if (! self::validFile($file) || $maxBytes < 1 || $timeoutSeconds < 1) {
            throw new OutboundRequestException('invalid_file_input', 'A supported ChatGPT file input is required.');
        }
        // One admission spans *both* signed download and the subsequent
        // Target operation. A rejected lease must never fetch the signed URL.
        $lease = $this->capacity->reserve($mode, $maxBytes, $timeoutSeconds);
        $stream = null;
        try {
            $stream = fopen('php://temp/maxmemory:65536', 'w+b');
            if ($stream === false) {
                throw new OutboundRequestException('file_staging_unavailable', 'Private file staging is unavailable.');
            }
            // The signed-source GET keeps its short-lived HTTPS budget even when
            // the subsequent SSH transfer has a longer Owner-selected deadline.
            $this->http->streamChatgptFile($file['download_url'], $maxBytes, $stream,
                $mode === 'ssh' ? min(120, $timeoutSeconds) : $timeoutSeconds);
            $stat = fstat($stream);
            if (! is_array($stat) || $stat['size'] < 0
                || $stat['size'] > $maxBytes || fseek($stream, 0) !== 0) {
                throw new OutboundRequestException('file_staging_unavailable', 'The private file could not be verified.');
            }
            $digest = hash_init('sha256');
            if (hash_update_stream($digest, $stream) < 0 || fseek($stream, 0) !== 0) {
                throw new OutboundRequestException('file_staging_unavailable', 'The private file could not be verified.');
            }

            return [
                'stream' => $stream, 'bytes' => $stat['size'],
                'sha256' => hash_final($digest), 'capacity_lease' => $lease,
            ];
        } catch (Throwable $exception) {
            if (is_resource($stream)) {
                fclose($stream);
            }
            $lease->release();

            throw $exception;
        }
    }
}
