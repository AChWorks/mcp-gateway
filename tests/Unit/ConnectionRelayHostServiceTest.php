<?php

namespace Tests\Unit;

use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayHostService;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

final class ConnectionRelayHostServiceTest extends TestCase
{
    public function test_service_is_persistent_and_uses_only_pinned_local_native_ssh(): void
    {
        $relay = new ConnectionRelay([
            'relay_id' => 'test-iran-relay',
            'control_host' => '45.11.186.243',
            'control_user' => 'root',
            'control_port' => 7770,
            'local_socks_port' => 46081,
        ]);
        $service = new ConnectionRelayHostService;
        self::assertSame('mcp-gateway-relay-test-iran-relay.service', $service->unitName($relay));
        $unit = $service->unitText($relay);
        self::assertStringContainsString('ExecStart=/usr/bin/ssh -N -T -D 127.0.0.1:46081', $unit);
        self::assertStringContainsString(' -p 7770 ', $unit);
        self::assertStringContainsString(' -o StrictHostKeyChecking=yes', $unit);
        self::assertStringContainsString(' -o UserKnownHostsFile=/etc/mcp-gateway-relays/test-iran-relay/known_hosts', $unit);
        self::assertStringContainsString('Restart=always', $unit);
        self::assertStringContainsString('WantedBy=multi-user.target', $unit);
        self::assertStringNotContainsString('PRIVATE KEY', $unit);
    }

    public function test_socket_ownership_requires_the_actual_listening_process(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);
        self::assertIsResource($socket);
        try {
            $name = stream_socket_get_name($socket, false);
            self::assertIsString($name);
            $port = (int) substr($name, strrpos($name, ':') + 1);
            $service = new ConnectionRelayHostService;
            $inodes = (new ReflectionMethod($service, 'listeningInodes'))->invoke($service, $port);
            self::assertNotEmpty($inodes, 'The real kernel socket inode must be discoverable.');
            $owns = new ReflectionMethod($service, 'pidOwnsSockets');
            self::assertTrue($owns->invoke($service, getmypid(), $inodes));
            self::assertFalse($owns->invoke($service, 0, $inodes));
            self::assertFalse($owns->invoke($service, getmypid(), ['9999999999999']));
            $foreign = new ReflectionMethod($service, 'managedServiceOwnsSockets');
            self::assertFalse($foreign->invoke($service, 'mcp-gateway-relay-not-installed.service', $inodes),
                'A foreign SOCKS listener cannot be attributed to a missing managed unit.');
        } finally {
            fclose($socket);
        }
    }

    public function test_untrusted_systemd_value_is_refused(): void
    {
        $relay = new ConnectionRelay([
            'relay_id' => 'unsafe',
            'control_host' => "relay.example.test\nExecStart=/bin/sh",
            'control_user' => 'root',
            'control_port' => 22,
            'local_socks_port' => 46081,
        ]);
        $this->expectException(RuntimeException::class);
        (new ConnectionRelayHostService)->unitText($relay);
    }
}
