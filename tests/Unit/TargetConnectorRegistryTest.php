<?php

namespace Tests\Unit;

use App\Application\Targets\TargetConnectorRegistry;
use App\Infrastructure\Connectors\SshDirect\SshDirectTargetAdapter;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetAdapter;
use InvalidArgumentException;
use Tests\TestCase;

final class TargetConnectorRegistryTest extends TestCase
{
    public function test_only_implemented_connectors_are_registered_and_resolved_once(): void
    {
        $registry = app(TargetConnectorRegistry::class);

        self::assertSame(['wp_ai_bridge', 'ssh_direct'], $registry->types());
        self::assertInstanceOf(WpAiBridgeTargetAdapter::class, $registry->forType('wp_ai_bridge'));
        self::assertInstanceOf(SshDirectTargetAdapter::class, $registry->forType('ssh_direct'));
        self::assertSame($registry->forType('ssh_direct'), $registry->forType('ssh_direct'));
        self::assertSame($registry->forType('wp_ai_bridge'), $registry->forType('wp_ai_bridge'));
    }

    public function test_unsupported_connector_is_never_dispatched(): void
    {
        $this->expectException(InvalidArgumentException::class);

        app(TargetConnectorRegistry::class)->forType('ai_server_agent');
    }
}
