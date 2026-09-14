<?php

namespace App\Infrastructure\Http;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

final class SafeHttpClient
{
    public function __construct(private readonly OutboundTargetPolicy $targets) {}

    /** @param array<string, string> $headers */
    public function get(string $url, array $headers = []): SafeHttpResponse
    {
        return $this->send('GET', $url, $headers, []);
    }

    /** @param array<string, scalar|null> $form @param array<string, string> $headers */
    public function postForm(string $url, array $form, array $headers = []): SafeHttpResponse
    {
        return $this->send('POST', $url, $headers, $form);
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, scalar|null> $form
     */
    private function send(string $method, string $url, array $headers, array $form): SafeHttpResponse
    {
        $target = $this->targets->validate($url);
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

        $connectTimeout = max(1, (int) config('bridge.http.connect_timeout_seconds', 2));
        $requestTimeout = max($connectTimeout, (int) config('bridge.http.request_timeout_seconds', 5));
        $maxBytes = max(1024, (int) config('bridge.http.max_response_bytes', 65536));

        $request = Http::withOptions([
            'allow_redirects' => false,
            'verify' => true,
            'stream' => true,
            ...($curlOptions === [] ? [] : ['curl' => $curlOptions]),
        ])
            ->connectTimeout($connectTimeout)
            ->timeout($requestTimeout)
            ->acceptJson()
            ->withHeaders($headers);

        try {
            $response = $method === 'POST'
                ? $request->asForm()->post($target->url, $form)
                : $request->get($target->url);
        } catch (ConnectionException $exception) {
            $message = $exception->getMessage();
            $reason = preg_match('/(?:SSL|TLS|certificate|cURL error 60)/i', $message) === 1 ? 'tls_failure' : 'network_failure';

            throw new OutboundRequestException($reason, 'Remote endpoint could not be reached.');
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

        $stream = $psrResponse->getBody();
        $body = '';
        try {
            while (! $stream->eof()) {
                $remaining = $maxBytes + 1 - strlen($body);
                if ($remaining <= 0) {
                    throw new OutboundRequestException('response_too_large', 'Remote response exceeded the configured size limit.');
                }
                $body .= $stream->read(min(8192, $remaining));
            }
        } finally {
            $stream->close();
        }

        if (strlen($body) > $maxBytes) {
            throw new OutboundRequestException('response_too_large', 'Remote response exceeded the configured size limit.');
        }

        return new SafeHttpResponse($status, $psrResponse->getHeaders(), $body);
    }
}
