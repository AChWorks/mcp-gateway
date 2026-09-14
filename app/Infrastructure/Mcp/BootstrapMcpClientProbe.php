<?php

namespace App\Infrastructure\Mcp;

use GuzzleHttp\Client as HttpClient;
use Mcp\Client;
use Mcp\Client\Transport\HttpTransport;

final class BootstrapMcpClientProbe
{
    /**
     * @return array{tool_names: list<string>, ping_status: string}
     */
    public function probe(string $endpoint, string $bearerToken): array
    {
        $connectTimeout = max(1, (int) config('mcp.client.connect_timeout_seconds'));
        $requestTimeout = max(1, (int) config('mcp.client.request_timeout_seconds'));

        $transport = new HttpTransport(
            endpoint: $endpoint,
            headers: ['Authorization' => 'Bearer '.$bearerToken],
            httpClient: new HttpClient([
                'connect_timeout' => $connectTimeout,
                'timeout' => $requestTimeout,
            ]),
        );

        $client = Client::builder()
            ->setClientInfo('mcp-gateway-bootstrap-probe', '0.1.0')
            ->setInitTimeout($connectTimeout)
            ->setRequestTimeout($requestTimeout)
            ->setMaxRetries(0)
            ->build();

        try {
            $client->connect($transport);

            $toolNames = array_values(array_map(
                static fn ($tool): string => $tool->name,
                $client->listTools()->tools,
            ));
            $ping = $client->callTool('gateway.bootstrap.ping');
            $structured = $ping->structuredContent;

            if (! is_array($structured) || ($structured['status'] ?? null) !== 'ok') {
                throw new \RuntimeException('Bootstrap MCP tool returned an unexpected response.');
            }

            return [
                'tool_names' => $toolNames,
                'ping_status' => 'ok',
            ];
        } finally {
            $client->disconnect();
        }
    }
}
