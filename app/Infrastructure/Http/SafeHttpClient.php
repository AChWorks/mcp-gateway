<?php

namespace App\Infrastructure\Http;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;

final class SafeHttpClient
{
    // Maximum decoded body accepted by a single shared-PHP request, regardless of env settings.
    public const ABSOLUTE_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    public function __construct(private readonly OutboundTargetPolicy $targets) {}

    /** @param array<string, string> $headers */
    public function get(string $url, array $headers = []): SafeHttpResponse
    {
        return $this->send('GET', $url, $headers, [], 'none');
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
    public function postJson(string $url, array $json, array $headers = [], ?int $responseLimitBytes = null): SafeHttpResponse
    {
        return $this->send('POST', $url, $headers, $json, 'json', $responseLimitBytes);
    }

    /** @param array<string, string> $headers */
    public function delete(string $url, array $headers = []): SafeHttpResponse
    {
        return $this->send('DELETE', $url, $headers, [], 'none');
    }

    /**
     * @param  array<string, string>  $headers
     * @param  array<string, mixed>  $payload
     * @param  'none'|'form'|'json'  $format
     */
    private function send(string $method, string $url, array $headers, array $payload, string $format, ?int $responseLimitBytes = null): SafeHttpResponse
    {
        $target = $this->targets->validate($url);
        $connectTimeout = max(1, (int) config('bridge.http.connect_timeout_seconds', 2));
        $requestTimeout = max($connectTimeout, (int) config('bridge.http.request_timeout_seconds', 5));
        $requestedBytes = $responseLimitBytes ?? (int) config('bridge.http.max_response_bytes', 65536);
        $maxBytes = min(self::ABSOLUTE_MAX_RESPONSE_BYTES, max(1024, $requestedBytes));
        $responseBody = new BoundedResponseBody($maxBytes);

        try {
            $curlOptions = [];
            if (filter_var($target->host, FILTER_VALIDATE_IP) === false) {
                if (! defined('CURLOPT_RESOLVE')) {
                    throw new OutboundRequestException('runtime', 'Secure outbound DNS pinning is unavailable.');
                }

                $resolveAddress = str_contains($target->pinnedAddress(), ':')
                    ? '['.$target->pinnedAddress().']'
                    : $target->pinnedAddress();
                $curlOptions[CURLOPT_RESOLVE] = [$target->host.':'.$target->port.':'.$resolveAddress];
            }

            $request = Http::withOptions([
                'allow_redirects' => false,
                'verify' => true,
                'proxy' => '',
                'progress' => [$responseBody, 'progress'],
                'sink' => $responseBody->stream(),
                ...($curlOptions === [] ? [] : ['curl' => $curlOptions]),
            ])
                ->connectTimeout($connectTimeout)
                ->timeout($requestTimeout)
                ->acceptJson()
                ->withHeaders($headers);

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
                $reason = preg_match('/(?:SSL|TLS|certificate|cURL error 60)/i', $message) === 1 ? 'tls_failure' : 'network_failure';

                throw new OutboundRequestException($reason, 'Remote endpoint could not be reached.');
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

            $stream = $responseBody->stream();
            if (! rewind($stream)) {
                throw new OutboundRequestException('network_failure', 'Remote response body could not be read.');
            }

            $body = stream_get_contents($stream);
            if ($body === false) {
                throw new OutboundRequestException('network_failure', 'Remote response body could not be read.');
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
