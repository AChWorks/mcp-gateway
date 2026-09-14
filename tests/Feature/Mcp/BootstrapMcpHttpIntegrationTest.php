<?php

namespace Tests\Feature\Mcp;

use App\Infrastructure\Mcp\BootstrapMcpClientProbe;
use GuzzleHttp\Client as HttpClient;
use Symfony\Component\Process\Process;
use Tests\TestCase;

final class BootstrapMcpHttpIntegrationTest extends TestCase
{
    public function test_fixture_is_not_exposed_when_disabled(): void
    {
        config()->set('mcp.bootstrap_fixture.enabled', false);

        $this->postJson('/_internal/mcp-bootstrap', [])
            ->assertNotFound();
    }

    public function test_fixture_rejects_an_invalid_bearer_token(): void
    {
        config()->set('mcp.bootstrap_fixture.enabled', true);
        config()->set('mcp.bootstrap_fixture.token', 'expected-token');

        $this->withToken('wrong-token')
            ->postJson('/_internal/mcp-bootstrap', [])
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Bearer');
    }

    public function test_official_mcp_client_can_list_tools_over_streamable_http_with_bearer_auth(): void
    {
        $port = $this->reserveLocalPort();
        $token = 'bootstrap-integration-token';
        $process = new Process(
            [PHP_BINARY, 'artisan', 'serve', '--host=127.0.0.1', '--port='.$port, '--tries=1', '--no-reload'],
            base_path(),
            [
                'APP_ENV' => 'testing',
                'APP_DEBUG' => 'false',
                'APP_KEY' => 'base64:'.base64_encode(str_repeat('k', 32)),
                'APP_URL' => 'http://127.0.0.1:'.$port,
                'DB_CONNECTION' => 'sqlite',
                'DB_DATABASE' => ':memory:',
                'MCP_BOOTSTRAP_FIXTURE_ENABLED' => 'true',
                'MCP_BOOTSTRAP_FIXTURE_TOKEN' => $token,
                'MCP_CLIENT_CONNECT_TIMEOUT_SECONDS' => '2',
                'MCP_CLIENT_REQUEST_TIMEOUT_SECONDS' => '5',
            ],
        );
        $process->setTimeout(15);
        $process->start();

        try {
            $this->waitUntilHealthy('http://127.0.0.1:'.$port.'/up', $process);

            $probe = app(BootstrapMcpClientProbe::class);
            $result = $probe->probe(
                'http://127.0.0.1:'.$port.'/_internal/mcp-bootstrap',
                $token,
            );

            $this->assertContains('gateway.bootstrap.ping', $result['tool_names']);
            $this->assertSame('ok', $result['ping_status']);
        } finally {
            $process->stop(1);
        }
    }

    private function reserveLocalPort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);

        $this->assertNotFalse($socket, sprintf('Could not reserve a local port: %s (%d)', $errorMessage, $errorCode));

        $address = stream_socket_get_name($socket, false);
        fclose($socket);

        $this->assertIsString($address);
        $port = (int) substr((string) strrchr($address, ':'), 1);
        $this->assertGreaterThan(0, $port);

        return $port;
    }

    private function waitUntilHealthy(string $url, Process $process): void
    {
        $client = new HttpClient([
            'connect_timeout' => 0.25,
            'timeout' => 0.5,
            'http_errors' => false,
        ]);

        for ($attempt = 0; $attempt < 40; $attempt++) {
            if (! $process->isRunning()) {
                $this->fail('Laravel fixture server exited early: '.$process->getErrorOutput().$process->getOutput());
            }

            try {
                if ($client->get($url)->getStatusCode() === 200) {
                    return;
                }
            } catch (\Throwable) {
                // The development server may need another short scheduling turn.
            }

            usleep(100000);
        }

        $this->fail('Laravel fixture server did not become healthy.');
    }
}
