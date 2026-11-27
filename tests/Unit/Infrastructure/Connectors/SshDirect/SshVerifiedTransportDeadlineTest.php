<?php

namespace Tests\Unit\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Connectors\SshDirect\SshAlgorithmPolicy;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class SshVerifiedTransportDeadlineTest extends TestCase
{
    public static function stalledPeers(): array
    {
        return [
            'partial identification' => ['SSH-2.0-fixture', false],
            'partial identification SFTP' => ['SSH-2.0-fixture', true],
            'partial KEX packet' => ["SSH-2.0-fixture\r\n\0\0\0", false],
        ];
    }

    #[DataProvider('stalledPeers')]
    public function test_incomplete_peer_input_cannot_outlive_the_original_budget(string $wire, bool $sftp): void
    {
        if (! function_exists('pcntl_fork')) {
            $this->markTestSkipped('Disposable local peer requires pcntl.');
        }
        $server = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($server);
        $address = (string) stream_socket_get_name($server, false);
        $port = (int) substr($address, strrpos($address, ':') + 1);
        $child = pcntl_fork();
        self::assertNotSame(-1, $child);
        if ($child === 0) {
            $peer = stream_socket_accept($server, 3);
            if (is_resource($peer)) {
                // A partial identification/packet arrives late enough that
                // an independent timeout per read would exceed the budget.
                usleep(300_000);
                @fwrite($peer, $wire);
                usleep(1_500_000);
                fclose($peer);
            }
            fclose($server);
            exit(0);
        }
        fclose($server);
        $policy = new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        };
        $transport = new SshVerifiedTransport($policy, new SshAlgorithmPolicy);
        $endpoint = SshRegisteredEndpoint::fromInput('fixture.example.test', $port, 'fixture');
        $pin = SshHostKeyPin::fromLine('ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('x', 32)));
        $start = hrtime(true);
        $deadline = $start + 600_000_000;
        $reason = null;
        $elapsed = 0;
        try {
            $never = static fn () => self::fail('Incomplete connection must not dispatch.');
            if ($sftp) {
                $transport->withAuthenticatedSftpSession($endpoint, $pin, 'password', 'fixture-password', null, $never, $deadline);
            } else {
                $transport->withAuthenticatedSession($endpoint, $pin, 'password', 'fixture-password', null, $never, deadlineNs: $deadline);
            }
            self::fail('Incomplete connection was accepted.');
        } catch (SshTargetConnectionException $exception) {
            $reason = $exception->reason;
            $elapsed = (hrtime(true) - $start) / 1_000_000_000;
        } finally {
            pcntl_waitpid($child, $status);
        }
        self::assertLessThan(1.05, $elapsed, 'Actual blocking read must use the original deadline, not a renewed read timeout.');
        self::assertSame('transfer_timed_out', $reason);
    }
}
