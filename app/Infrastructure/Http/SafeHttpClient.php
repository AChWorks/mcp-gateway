<?php

namespace App\Infrastructure\Http;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;

final class SafeHttpClient
{
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
    public function postJson(string $url, array $json, array $headers = []): SafeHttpResponse
    {
        return $this->send('POST', $url, $headers, $json, 'json');
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
    private function send(string $method, string $url, array $headers, array $payload, string $format): SafeHttpResponse
    {
        $target = $this->targets->validate($url);
        $connectTimeout = max(1, (int) config('bridge.http.connect_timeout_seconds', 2));
        $requestTimeout = max($connectTimeout, (int) config('bridge.http.request_timeout_seconds', 5));
        $maxBytes = max(1024, (int) config('bridge.http.max_response_bytes', 65536));
        $responseBody = new BoundedResponseBody($maxBytes);

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
                throw new OutboundRequestException('response_too_large', 'Remote response exceeded the configured size limit.');
            }

            if ($exception instanceof RequestException) {
                throw $exception;
            }

            $message = $exception->getMessage();
            $reason = preg_match('/(?:SSL|TLS|certificate|cURL error 60)/i', $message) === 1 ? 'tls_failure' : 'network_failure';

            throw new OutboundRequestException($reason, 'Remote endpoint could not be reached.');
        }

        if ($responseBody->limitExceeded()) {
            throw new OutboundRequestException('response_too_large', 'Remote response exceeded the configured size limit.');
        }

        $status = $response->status();
        if ($status >= 300 && $status < 400) {
            throw new OutboundRequestException('unsafe_redirect', 'Remote endpoint attempted an unsupported redirect.');
        }

        $psrResponse = $response->toPsrResponse();
        $lengthHeader = $psrResponse->getHeaderLine('Content-Length');
        if ($lengthHeader !== '' && ctype_digit($lengthHeader) && (int) $lengthHeader > $maxBytes) {
            throw new OutboundRequestException('response_too_large', 'Remote response exceeded the configured size limit.');
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
            throw new OutboundRequestException('response_too_large', 'Remote response exceeded the configured size limit.');
        }

        return new SafeHttpResponse($status, $psrResponse->getHeaders(), $body);
    }
}
