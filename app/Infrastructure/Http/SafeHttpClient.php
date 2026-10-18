<?php

namespace App\Infrastructure\Http;

use App\Application\Operations\OperationalSettings;
use App\Support\OperationTiming;
use GuzzleHttp\Exception\ConnectException as GuzzleConnectException;
use GuzzleHttp\TransferStats;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;

final class SafeHttpClient
{
    // Maximum decoded body accepted by a single shared-PHP request, regardless of env settings.
    public const ABSOLUTE_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    public function __construct(
        private readonly OutboundTargetPolicy $targets,
        private readonly OperationalSettings $settings,
    ) {}

    /** @param array<string, string> $headers */
    public function get(string $url, array $headers = []): SafeHttpResponse
    {
        return $this->send('GET', $url, $headers, [], 'none');
    }

    /** Only the allowlisted ChatGPT file origin may include signed queries. */
    public function getChatgptFile(string $url, int $maxBytes): SafeHttpResponse
    {
        return $this->send('GET', $url, [], [], 'none', $maxBytes, null, true);
    }

    /**
     * Stream one allowlisted host file into the caller-owned, bounded private spool.
     * Unlike the normal JSON response path, the body is never materialized as a string.
     * The caller must close its spool, validate the status, byte count and SHA-256.
     *
     * @param  resource  $sink
     */
    public function streamChatgptFile(string $url, int $maxBytes, mixed $sink, int $timeoutSeconds): SafeHttpResponse
    {
        if (! is_resource($sink) || $maxBytes < 1 || $timeoutSeconds < 1) {
            throw new OutboundRequestException('file_staging_unavailable', 'Private file staging is unavailable.');
        }

        return $this->send('GET', $url, [], [], 'none', $maxBytes, null, true, $sink, $timeoutSeconds);
    }

    /**
     * @param  array<string, scalar|null>  $form
     * @param  array<string, string>  $headers
     */
    public function postForm(string $url, array $form, array $headers = []): SafeHttpResponse
    {
        return $this->send('POST', $url, $headers, $form, 'form');
    }

    /**
     * @param  array<string, mixed>  $json
     * @param  array<string, string>  $headers
     */
    public function postJson(string $url, array $json, array $headers = [], ?int $responseLimitBytes = null, ?OperationTiming $timing = null): SafeHttpResponse
    {
        return $this->send('POST', $url, $headers, $json, 'json', $responseLimitBytes, $timing);
    }

    /** @param array<string, string> $headers */
    public function delete(string $url, array $headers = [], ?OperationTiming $timing = null): SafeHttpResponse
    {
        return $this->send('DELETE', $url, $headers, [], 'none', null, $timing);
    }

    /**
     * @param  array<string, string>  $headers
     * @param  array<string, mixed>  $payload
     * @param  'none'|'form'|'json'  $format
     */
    private function send(string $method, string $url, array $headers, array $payload, string $format, ?int $responseLimitBytes = null, ?OperationTiming $timing = null, bool $chatgptFile = false, mixed $fileSink = null, ?int $fileTimeoutSeconds = null): SafeHttpResponse
    {
        $network = $this->settings->httpTimeoutsSeconds();
        $connectTimeout = $network['connect'];
        $requestTimeout = $fileTimeoutSeconds ?? $network['request'];
        $startedNs = hrtime(true);
        if ($requestTimeout > intdiv(PHP_INT_MAX - $startedNs, 1_000_000_000)) {
            throw new OutboundRequestException('runtime', 'Outbound request timeout configuration is invalid.', [], true);
        }
        $deadlineNs = $startedNs + $requestTimeout * 1_000_000_000;

        // DNS and HTTPS share one request lifetime; inspect all A+AAAA records
        // before selecting the numeric, TLS-validated destination.
        $dnsStarted = $timing?->stamp() ?? 0;
        try {
            $target = $chatgptFile
                ? $this->targets->validateChatgptFileUrl($url, $deadlineNs)
                : $this->targets->validate($url, 2048, $deadlineNs);
        } finally {
            $timing?->finish('dns_policy_ms', $dnsStarted);
        }
        $remainingSeconds = ($deadlineNs - hrtime(true)) / 1_000_000_000;
        if ($remainingSeconds <= 0) {
            throw new OutboundRequestException('network_failure', 'Outbound request deadline expired before dispatch.', ['failure_stage' => 'deadline_before_dispatch'], true);
        }
        $requestedBytes = $responseLimitBytes ?? $this->settings->responseLimitBytes(false);
        // The 8 MiB bound still applies to all ordinary in-memory responses.
        // A file sink has a separate finite caller-authorized whole-file budget.
        $maxBytes = $fileSink === null
            ? min(self::ABSOLUTE_MAX_RESPONSE_BYTES, max(1024, $requestedBytes))
            : max(1, $requestedBytes);
        // FileParams must have ONE caller-owned bounded spool. Sending into
        // an intermediate BoundedResponseBody spool and copying later would
        // double temporary disk usage before the WP capacity ledger notices.
        $responseBody = new BoundedResponseBody($maxBytes, $fileSink);

        try {
            $curlOptions = [];
            if (filter_var($target->host, FILTER_VALIDATE_IP) === false) {
                if (! defined('CURLOPT_RESOLVE')) {
                    throw new OutboundRequestException('runtime', 'Secure outbound DNS pinning is unavailable.', [], true);
                }

                $resolveAddress = str_contains($target->pinnedAddress(), ':')
                    ? '['.$target->pinnedAddress().']'
                    : $target->pinnedAddress();
                $curlOptions[CURLOPT_RESOLVE] = [$target->host.':'.$target->port.':'.$resolveAddress];
            }

            $request = Http::withOptions([
                'allow_redirects' => false,
                'verify' => true,
                // Never transparently decompress an opaque signed-file byte stream.
                ...($fileSink === null ? [] : ['decode_content' => false]),
                'proxy' => '',
                'progress' => [$responseBody, 'progress'],
                'sink' => $responseBody->stream(),
                ...($curlOptions === [] ? [] : ['curl' => $curlOptions]),
                ...($timing === null ? [] : [
                    'on_stats' => static function (TransferStats $stats) use ($timing): void {
                        $timing->curlStats($stats->getHandlerStats());
                    },
                ]),
            ])
                ->connectTimeout(min($connectTimeout, $remainingSeconds))
                ->timeout($remainingSeconds)
                ->accept($chatgptFile ? '*/*' : 'application/json')
                ->withHeaders($chatgptFile ? ['Accept-Encoding' => 'identity', ...$headers] : $headers);

            $httpStarted = $timing?->stamp() ?? 0;
            $timing?->outboundCall();
            try {
                $response = match ($method) {
                    'POST' => $format === 'json'
                        ? $request->asJson()->post($target->url, $payload)
                        : $request->asForm()->post($target->url, $payload),
                    'DELETE' => $request->delete($target->url),
                    default => $request->get($target->url),
                };
            } catch (ConnectionException|RequestException $exception) {
                if ($responseBody->limitExceeded()) {
                    throw $this->oversize($maxBytes, $responseBody->limitPhase() ?? 'decoded_body', $responseBody->observedBytes());
                }

                if ($exception instanceof RequestException) {
                    throw $exception;
                }

                $message = $exception->getMessage();
                $reason = preg_match('/(?:SSL|TLS|certificate|cURL error (?:35|51|60)\\b)/i', $message) === 1 ? 'tls_failure' : 'network_failure';

                // The exact Guzzle cURL handler uses ConnectException
                // (including ConnectTimeoutException) only when the TCP/TLS
                // connection was never established. A token request could not
                // have reached its destination. Other transport failures may
                // occur after the request body was transmitted.
                $preDispatch = $exception->getPrevious() instanceof GuzzleConnectException;

                // Retain only a finite transport stage, never raw cURL text,
                // remote response, request headers, URLs or credentials.
                $stage = match (true) {
                    preg_match('/(?:cURL error 6\\b|could not resolve)/i', $message) === 1 => 'dns_lookup',
                    $reason === 'tls_failure' => 'tls_handshake',
                    preg_match('/(?:cURL error 7\\b|connection refused|failed to connect)/i', $message) === 1 => 'tcp_connect',
                    preg_match('/(?:cURL error 28\\b|timed out|timeout)/i', $message) === 1 => 'request_timeout',
                    $preDispatch => 'connection_setup',
                    default => 'response_transfer',
                };

                throw new OutboundRequestException($reason, 'Remote endpoint could not be reached.', [
                    'failure_stage' => $stage,
                ], $preDispatch);
            } finally {
                $timing?->finish('http_transport_ms', $httpStarted);
            }

            if ($responseBody->limitExceeded()) {
                throw $this->oversize($maxBytes, $responseBody->limitPhase() ?? 'decoded_body', $responseBody->observedBytes());
            }

            $status = $response->status();
            if ($status >= 300 && $status < 400) {
                throw new OutboundRequestException('unsafe_redirect', 'Remote endpoint attempted an unsupported redirect.');
            }

            $psrResponse = $response->toPsrResponse();
            $lengthHeader = $psrResponse->getHeaderLine('Content-Length');
            if ($lengthHeader !== '' && ctype_digit($lengthHeader) && (int) $lengthHeader > $maxBytes) {
                throw $this->oversize($maxBytes, 'content_length', (int) $lengthHeader);
            }

            if (is_resource($fileSink)) {
                // Guzzle wrote every decoded byte directly through our size
                // filter into the SAME caller-owned spool. It remains private
                // and is discarded by the caller if status/encoding/length
                // checks fail. No intermediate on-disk copy ever exists.
                if ($status !== 200) {
                    throw new OutboundRequestException('file_download_unavailable', 'The signed private file was not available.');
                }
                $encoding = strtolower($psrResponse->getHeaderLine('Content-Encoding'));
                if ($encoding !== '' && $encoding !== 'identity') {
                    throw new OutboundRequestException('unsupported_content_encoding', 'Compressed private file responses are unsupported.');
                }
                $received = $responseBody->decodedBytes();
                $stat = fstat($fileSink);
                // Some HTTP handlers rewind their sink when constructing a
                // PSR-7 response. Use fstat as the authoritative persisted
                // length and restore the caller's expected EOF cursor.
                if (! is_array($stat) || $stat['size'] !== $received
                    || fseek($fileSink, 0, SEEK_END) !== 0
                    || ftell($fileSink) !== $received) {
                    throw new OutboundRequestException('file_staging_unavailable', 'Private file staging could not be verified.');
                }
                if ($lengthHeader !== '' && (! ctype_digit($lengthHeader) || (int) $lengthHeader !== $received)) {
                    throw new OutboundRequestException('file_download_incomplete', 'Private file length did not match the response.');
                }
                if ($received > $maxBytes) {
                    throw $this->oversize($maxBytes, 'collected_body', $received);
                }

                return new SafeHttpResponse($status, $psrResponse->getHeaders(), '');
            }

            $stream = $responseBody->stream();
            if (! rewind($stream)) {
                throw new OutboundRequestException('network_failure', 'Remote response body could not be read.', ['failure_stage' => 'response_body']);
            }

            $body = stream_get_contents($stream);
            if ($body === false) {
                throw new OutboundRequestException('network_failure', 'Remote response body could not be read.', ['failure_stage' => 'response_body']);
            }

            if (strlen($body) > $maxBytes) {
                throw $this->oversize($maxBytes, 'collected_body', strlen($body));
            }

            return new SafeHttpResponse($status, $psrResponse->getHeaders(), $body);
        } finally {
            $responseBody->close();
        }
    }

    private function oversize(int $limitBytes, string $phase, ?int $observedBytes): OutboundRequestException
    {
        $details = ['limit_bytes' => $limitBytes, 'phase' => $phase];
        if ($observedBytes !== null) {
            $details['observed_bytes'] = $observedBytes;
        }

        return new OutboundRequestException(
            'response_too_large',
            'Remote response exceeded the configured size limit.',
            $details,
        );
    }
}
