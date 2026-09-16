<?php

namespace Tests\Feature\Sites;

use App\Infrastructure\Http\BoundedResponseBody;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ResponseException;
use Symfony\Component\Process\Process;
use Tests\TestCase;

final class BoundedResponseTransportTest extends TestCase
{
    public function test_real_guzzle_transport_bounds_decoded_and_unknown_length_bodies(): void
    {
        self::assertLessThanOrEqual(
            1024,
            strlen(gzencode(str_repeat('g', 8192), 9)),
            'Fixture must remain small on the wire so decoded-byte enforcement, not wire progress, closes the gzip case.',
        );

        $port = $this->reserveLocalPort();
        $process = new Process(
            [PHP_BINARY, '-S', '127.0.0.1:'.$port, base_path('tests/Support/bounded_response_fixture.php')],
            base_path(),
        );
        $process->setTimeout(15);
        $process->start();

        try {
            $this->waitUntilHealthy($port, $process);
            $client = new Client([
                'connect_timeout' => 1,
                'timeout' => 5,
                'http_errors' => false,
            ]);

            $gzipOver = new BoundedResponseBody(1024);
            try {
                $client->get('http://127.0.0.1:'.$port.'/gzip-over', [
                    'sink' => $gzipOver->stream(),
                    'progress' => [$gzipOver, 'progress'],
                ]);
                self::fail('Compressed response expanded beyond the decoded-byte limit without aborting.');
            } catch (ResponseException $exception) {
                self::assertTrue($gzipOver->limitExceeded());
                self::assertLessThanOrEqual(1024, $this->storedBytes($gzipOver));
            }

            $gzipExact = new BoundedResponseBody(1024);
            $response = $client->get('http://127.0.0.1:'.$port.'/gzip-exact', [
                'sink' => $gzipExact->stream(),
                'progress' => [$gzipExact, 'progress'],
            ]);
            self::assertSame(200, $response->getStatusCode());
            self::assertFalse($gzipExact->limitExceeded());
            self::assertSame(1024, $gzipExact->decodedBytes());
            self::assertSame(1024, $this->storedBytes($gzipExact));

            $unknownOver = new BoundedResponseBody(1024);
            try {
                $client->get('http://127.0.0.1:'.$port.'/unknown-over', [
                    'sink' => $unknownOver->stream(),
                    'progress' => [$unknownOver, 'progress'],
                ]);
                self::fail('Unknown-length response exceeded the configured limit without aborting.');
            } catch (ResponseException $exception) {
                self::assertSame('', $exception->getResponse()->getHeaderLine('Content-Length'));
                self::assertTrue($unknownOver->limitExceeded());
                self::assertLessThanOrEqual(1024, $this->storedBytes($unknownOver));
            }
        } finally {
            $process->stop(1);
        }
    }

    private function reserveLocalPort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        self::assertNotFalse($socket, sprintf('Could not reserve a local port: %s (%d)', $errorMessage, $errorCode));

        $address = stream_socket_get_name($socket, false);
        fclose($socket);

        self::assertIsString($address);
        $port = (int) substr((string) strrchr($address, ':'), 1);
        self::assertGreaterThan(0, $port);

        return $port;
    }

    private function waitUntilHealthy(int $port, Process $process): void
    {
        $client = new Client([
            'connect_timeout' => 0.25,
            'timeout' => 0.5,
            'http_errors' => false,
        ]);

        for ($attempt = 0; $attempt < 40; $attempt++) {
            if (! $process->isRunning()) {
                self::fail('Bounded-response fixture server exited early: '.$process->getErrorOutput().$process->getOutput());
            }

            try {
                if ($client->get('http://127.0.0.1:'.$port.'/health')->getStatusCode() === 200) {
                    return;
                }
            } catch (\Throwable) {
                // The local server may need another scheduling turn.
            }

            usleep(100000);
        }

        self::fail('Bounded-response fixture server did not become healthy.');
    }

    private function storedBytes(BoundedResponseBody $body): int
    {
        $stream = $body->stream();
        self::assertTrue(rewind($stream));
        $contents = stream_get_contents($stream);
        self::assertIsString($contents);

        return strlen($contents);
    }
}
