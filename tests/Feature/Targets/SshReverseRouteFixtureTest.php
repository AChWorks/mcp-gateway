<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshAlgorithmPolicy;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshHostKeyPin;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;
use App\Infrastructure\Connectors\SshDirect\SshVerifiedTransport;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Actual OpenSSH -R from an unprivileged fixture client into a second sshd.
 * The registered endpoint still denotes the far target; no blanket loopback
 * egress exception is used and no network call to the original FQDN is made.
 */
final class SshReverseRouteFixtureTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        if (getenv('SSH_FIXTURE_ENABLED') !== '1' || getenv('SSH_FIXTURE_REVERSE_PORT') === false) {
            $this->markTestSkipped('Isolated client-initiated OpenSSH reverse fixture not configured.');
        }
        config()->set('ssh.reverse_approved_routes', json_encode([
            'fixture-reverse' => [
                'port' => (int) getenv('SSH_FIXTURE_REVERSE_PORT'),
                'tunnel_identity' => 'test-loopback-forward',
            ],
        ], JSON_THROW_ON_ERROR));
    }

    public function test_client_initiated_openssh_r_supports_pinned_login_exec_and_sftp_without_reporting_listener_as_target_ip(): void
    {
        $controlKey = trim((string) file_get_contents((string) getenv('SSH_FIXTURE_REVERSE_CONTROL_HOST_PUB')));
        $targetKey = trim((string) file_get_contents((string) getenv('SSH_FIXTURE_ED25519_HOST_PUB')));
        self::assertNotSame($controlKey, $targetKey,
            'Tunnel control SSHD host key must differ from pinned remote Target SSHD host key.');

        $owner = User::query()->create([
            'name' => 'Reverse route fixture',
            'email' => 'reverse-'.Str::random(12).'@example.test',
            'password' => 'FixtureOwner!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
        $target = app(SshTargetRegistration::class)->register(
            'fixture-reverse', 'Fixture Reverse',
            'fixture.example.test', (int) getenv('SSH_FIXTURE_PORT_MODERN'),
            (string) getenv('SSH_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_FIXTURE_ED25519_HOST_PUB'))),
            'password', (string) getenv('SSH_FIXTURE_PASSWORD'), null,
            null, 'reverse', (int) getenv('SSH_FIXTURE_REVERSE_PORT'), 'test-loopback-forward',
        );

        // Successful login over OpenSSH -R must not persist 127.0.0.1 as
        // the Target's actual observed network identity.
        self::assertSame('127.0.0.1', app(SshTargetConnectionService::class)->test($target));
        $target->refresh();
        self::assertSame(TargetConnectionState::Connected, $target->connection_state);
        $config = SshTargetConfig::query()->sole();
        self::assertNull($config->observed_peer_ip);
        self::assertNotNull($config->observed_at);
        $identity = SshTargetIdentity::safeMetadata($target->load('sshConfig'));
        self::assertSame('reverse', $identity['route_mode']);
        self::assertSame('reverse_route_verified', $identity['ip_status']);
        self::assertNotSame('127.0.0.1', $identity['ip']);

        $command = app(SshCommandRuntime::class)->run($owner, $target, 'printf reverse_forward_exec_passed');
        self::assertSame('completed', $command['status']);
        self::assertSame('reverse_forward_exec_passed', $command['stdout']);
        self::assertNull($command['connected_ip']);
        self::assertSame('reverse', $command['route_mode']);
        $file = app(SshFileRuntime::class)->stat($owner, $target, '/home/'.getenv('SSH_FIXTURE_USER'));
        self::assertSame('directory', $file['file']['type']);
        self::assertNull($file['connected_ip']);
        self::assertSame('reverse', $file['route_mode']);
    }

    public function test_wrong_pinned_remote_server_is_rejected_before_credential_exchange_across_real_reverse_forward(): void
    {
        $serverLog = (string) getenv('SSH_FIXTURE_LOG_MODERN');
        clearstatcache(true, $serverLog);
        $offset = (int) filesize($serverLog);
        config()->set('ssh.reverse_approved_routes', json_encode([
            'fixture-wrong-pin' => [
                'port' => (int) getenv('SSH_FIXTURE_REVERSE_PORT'),
                'tunnel_identity' => 'test-loopback-forward',
            ],
        ], JSON_THROW_ON_ERROR));
        $target = app(SshTargetRegistration::class)->register(
            'fixture-wrong-pin', 'Wrong pin fixture',
            'fixture.example.test', (int) getenv('SSH_FIXTURE_PORT_MODERN'),
            (string) getenv('SSH_FIXTURE_USER'),
            trim((string) file_get_contents((string) getenv('SSH_FIXTURE_WRONG_ED25519_HOST_PUB'))),
            'password', (string) getenv('SSH_FIXTURE_PASSWORD'), null,
            null, 'reverse', (int) getenv('SSH_FIXTURE_REVERSE_PORT'), 'test-loopback-forward',
        );

        try {
            app(SshTargetConnectionService::class)->test($target);
            self::fail('Server trust mismatch unexpectedly authenticated over the listener.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('host_key_mismatch', $exception->reason);
        }
        usleep(100000);
        $tail = (string) substr((string) file_get_contents($serverLog), $offset);
        self::assertDoesNotMatchRegularExpression(
            '/(?:Accepted|Failed) (?:password|publickey)|authentication failure/i', $tail,
        );
    }

    public function test_disconnected_approved_listener_fails_closed_without_public_dns_fallback(): void
    {
        $policy = new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                throw new \RuntimeException('Public address policy must not be called for reverse listener.');
            }
        };
        // Reserved test port is not allocated by the fixture daemon.
        $port = 46252;
        config()->set('ssh.reverse_approved_routes', json_encode([
            'fixture-reverse' => ['port' => $port, 'tunnel_identity' => 'absent-listener'],
        ], JSON_THROW_ON_ERROR));
        $route = app(SshReverseRoutePolicy::class)->approve('fixture-reverse', 'reverse', $port, 'absent-listener');
        $transport = new SshVerifiedTransport($policy, app(SshAlgorithmPolicy::class));
        try {
            $transport->authenticate(
                SshRegisteredEndpoint::fromInput('fixture.example.test', 22, (string) getenv('SSH_FIXTURE_USER')),
                SshHostKeyPin::fromLine(trim((string) file_get_contents((string) getenv('SSH_FIXTURE_ED25519_HOST_PUB')))),
                'password', (string) getenv('SSH_FIXTURE_PASSWORD'), null, $route,
            );
            self::fail('Missing listener unexpectedly connected.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('reverse_listener_unavailable', $exception->reason);
        }
    }
}
