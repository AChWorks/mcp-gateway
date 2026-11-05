<?php

namespace Tests\Unit;

use App\Infrastructure\Connectors\Relay\ConnectionRelay;
use App\Infrastructure\Connectors\Relay\ConnectionRelayOperationalState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConnectionRelayOperationalStateTest extends TestCase
{
    #[DataProvider('states')]
    public function test_status_is_bounded_by_actual_evidence(
        bool $enabled, int $configurationRevision, int $lifecycleRevision,
        bool $hostReady, bool $deletionFenced, ConnectionRelayOperationalState $expected,
    ): void {
        $relay = new ConnectionRelay;
        $relay->enabled = $enabled;
        $relay->configuration_revision = $configurationRevision;
        $relay->lifecycle_revision = $lifecycleRevision;

        self::assertSame($expected, ConnectionRelayOperationalState::assess($relay, $hostReady, $deletionFenced));
    }

    /** @return array<string,array{bool,int,int,bool,bool,ConnectionRelayOperationalState}> */
    public static function states(): array
    {
        return [
            'initial registration is an unverified draft' => [false, 1, 1, false, false, ConnectionRelayOperationalState::Draft],
            'initial registration with trusted evidence' => [false, 1, 1, true, false, ConnectionRelayOperationalState::Ready],
            'disabled after prior lifecycle' => [false, 2, 2, false, false, ConnectionRelayOperationalState::NeedsSetup],
            'enabled and attested, target still unverified' => [true, 2, 3, true, false, ConnectionRelayOperationalState::Enabled],
            'enabled with expired evidence fails closed' => [true, 2, 3, false, false, ConnectionRelayOperationalState::Degraded],
            'terminal fence awaiting record removal' => [false, 2, 3, false, true, ConnectionRelayOperationalState::CleanupRequired],
            'unexpected enabled plus deletion fence' => [true, 2, 3, true, true, ConnectionRelayOperationalState::Degraded],
        ];
    }
}
