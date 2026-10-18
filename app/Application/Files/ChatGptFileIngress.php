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
    public function __construct(private SafeHttpClient $http) {}

    /** @param array<string,mixed> $file */
    public static function validFile(array $file): bool
    {
        $id = $file['file_id'] ?? null;
        $url = $file['download_url'] ?? null;
        if (! is_string($id) || strlen($id) < 1 || strlen($id) > 255
            || ! is_string($url) || strlen($url) < 1 || strlen($url) > 8192
            || strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https'
            || strtolower((string) parse_url($url, PHP_URL_HOST)) !== 'files.oaiusercontent.com'
            || parse_url($url, PHP_URL_USER) !== null
            || parse_url($url, PHP_URL_PASS) !== null
            || parse_url($url, PHP_URL_PORT) !== null
            || parse_url($url, PHP_URL_FRAGMENT) !== null
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

    /**
     * @param  array<string,mixed>  $file
     * @return array{stream:resource,bytes:int,sha256:string}
     *
     * @throws OutboundRequestException
     */
    public function download(array $file, int $maxBytes, int $timeoutSeconds): array
    {
        if (! self::validFile($file) || $maxBytes < 1 || $timeoutSeconds < 1) {
            throw new OutboundRequestException('invalid_file_input', 'A supported ChatGPT file input is required.');
        }
        $stream = fopen('php://temp/maxmemory:65536', 'w+b');
        if ($stream === false) {
            throw new OutboundRequestException('file_staging_unavailable', 'Private file staging is unavailable.');
        }
        try {
            $this->http->streamChatgptFile($file['download_url'], $maxBytes, $stream, $timeoutSeconds);
            $stat = fstat($stream);
            if (! is_array($stat) || $stat['size'] < 0
                || $stat['size'] > $maxBytes || fseek($stream, 0) !== 0) {
                throw new OutboundRequestException('file_staging_unavailable', 'The private file could not be verified.');
            }
            $digest = hash_init('sha256');
            if (hash_update_stream($digest, $stream) < 0 || fseek($stream, 0) !== 0) {
                throw new OutboundRequestException('file_staging_unavailable', 'The private file could not be verified.');
            }

            return ['stream' => $stream, 'bytes' => $stat['size'], 'sha256' => hash_final($digest)];
        } catch (Throwable $exception) {
            fclose($stream);
            throw $exception;
        }
    }
}
