<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\TargetTransportBinding;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\Relay\ConnectionRelayRoutes;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use App\Infrastructure\Http\OutboundRequestException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class TargetTransportMigrationTest extends TestCase
{
    private string $originalConnection;

    private const CONNECTION = 'transport_migration_fixture';

    private const SECRET = 'migration-fixture-login';

    protected function setUp(): void
    {
        parent::setUp();
        // Always use a new isolated SQLite schema, including during MariaDB CI.
        $this->originalConnection = DB::getDefaultConnection();
        config()->set('database.connections.'.self::CONNECTION, [
            'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true,
        ]);
        DB::setDefaultConnection(self::CONNECTION);
        Schema::clearResolvedInstance('db.schema');
        $baseline = require database_path('migrations/0001_01_01_000001_create_gateway_v3_schema.php');
        $baseline->up();
    }

    protected function tearDown(): void
    {
        DB::purge(self::CONNECTION);
        DB::setDefaultConnection($this->originalConnection);
        Schema::clearResolvedInstance('db.schema');
        parent::tearDown();
    }

    public function test_released_credentials_routes_and_retained_job_identity_survive_upgrade(): void
    {
        $relayId = (string) Str::ulid();
        DB::table('connection_relays')->insert([
            'id' => $relayId, 'relay_id' => 'migration-relay', 'display_name' => 'Migration fixture',
            'control_host' => '1.1.1.1', 'control_port' => 22, 'control_user' => 'fixture',
            'control_host_key' => $this->hostKey(), 'local_socks_port' => 46900, 'enabled' => true,
        ]);
        $records = [
            $this->legacy('direct', 0, null, 0),
            $this->legacy('direct', 3, $relayId, 5),
            $this->legacy('reverse', 2, null, 4),
        ];
        $this->upgrade();
        self::assertFalse(Schema::hasColumn('ssh_direct_target_configs', 'route_mode'));
        self::assertFalse(Schema::hasColumn('targets', 'relay_binding_revision'));
        self::assertTrue(Schema::hasIndex('targets', 'target_reverse_unique_port'));

        foreach ($records as $record) {
            $target = Target::query()->findOrFail($record['id']);
            $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole();
            $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
            self::assertSame($record['credential'], $credential->getKey());
            self::assertSame('connected', $target->connection_state->value);
            self::assertSame($record['epoch'], $target->transport_revision);
            self::assertSame($record['kind'], $target->transportKind());
            self::assertSame($record['port'], $target->reverse_listener_port);
            self::assertSame($record['digest'], SshTargetBinding::hash($target, $config));
            self::assertSame(self::SECRET, app(SshTargetVault::class)->open($target, $config, $credential)['secret']);
        }

        $reverse = Target::query()->findOrFail($records[2]['id']);
        $credential = TargetCredential::query()->where('target_record_id', $reverse->getKey())->sole();
        $cipher = $credential->encrypted_payload;
        $binding = app(TargetTransportBinding::class);
        self::assertTrue($binding->change($reverse, $binding->revision($reverse), 'migration-relay'));
        $reverse->refresh();
        self::assertSame('relay', $reverse->transportKind());
        self::assertSame(5, $reverse->transport_revision);
        self::assertSame('connected', $reverse->connection_state->value);
        self::assertSame($cipher, $credential->fresh()->encrypted_payload);
        self::assertNotSame($records[2]['digest'], SshTargetBinding::hash($reverse, $reverse->sshConfig));
    }

    public function test_invalid_legacy_envelope_aborts_conversion_without_partial_credential_loss(): void
    {
        $valid = $this->legacy('direct', 1, null, 0);
        $invalid = $this->legacy('reverse', 0, null, 0);
        DB::table('target_credentials')->where('id', $invalid['credential'])->update(['encrypted_payload' => 'invalid-fixture']);
        $before = DB::table('target_credentials')->where('id', $valid['credential'])->value('encrypted_payload');
        try {
            (require database_path('migrations/0001_01_01_000004_detach_ssh_login_from_transport.php'))->up();
            self::fail('Invalid old credential was silently reinterpreted.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Cannot migrate SSH login', $exception->getMessage());
        }
        self::assertSame($before, DB::table('target_credentials')->where('id', $valid['credential'])->value('encrypted_payload'));
        self::assertSame(2, DB::table('target_credentials')->count());
        self::assertTrue(Schema::hasColumn('targets', 'relay_binding_revision'));
    }

    public function test_fixed_reverse_path_does_not_silently_fall_back_for_an_http_connector(): void
    {
        $this->upgrade();
        $target = Target::query()->create([
            'target_id' => 'http-path-fixture', 'display_name' => 'HTTP path fixture',
            'connector_type' => 'wp_ai_bridge', 'connection_state' => 'connected',
        ]);
        DB::transaction(function () use ($target): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->sole();
            app(TargetTransportBinding::class)->changeReverseLocked($locked, 62499, 'fixed-listener');
        });
        $target->refresh();
        self::assertSame('reverse', $target->transportKind());
        self::assertSame('connected', $target->connection_state->value);
        try {
            app(ConnectionRelayRoutes::class)->httpRouteForTarget($target);
            self::fail('Incompatible fixed listener silently degraded to Direct.');
        } catch (OutboundRequestException $exception) {
            self::assertStringContainsString('incompatible', $exception->getMessage());
        }
    }

    private function upgrade(): void
    {
        foreach (['000004_detach_ssh_login_from_transport', '000005_move_reverse_to_target_transport'] as $migration) {
            (require database_path('migrations/0001_01_01_'.$migration.'.php'))->up();
        }
    }

    /** @return array{id:string,credential:string,epoch:int,kind:string,port:?int,digest:string} */
    private function legacy(string $mode, int $identityEpoch, ?string $relay, int $epoch): array
    {
        $id = (string) Str::ulid();
        $slug = 'legacy-'.strtolower((string) Str::ulid());
        $credential = (string) Str::ulid();
        $port = $mode === 'reverse' ? 62398 : null;
        $identity = $port === null ? null : 'legacy-reverse';
        DB::table('targets')->insert([
            'id' => $id, 'target_id' => $slug, 'display_name' => 'Legacy fixture',
            'connector_type' => 'ssh_direct', 'connection_state' => 'connected',
            'relay_record_id' => $relay, 'relay_binding_revision' => $epoch,
            'connected_at' => now(), 'last_tested_at' => now(),
        ]);
        DB::table('ssh_direct_target_configs')->insert([
            'id' => (string) Str::ulid(), 'target_record_id' => $id, 'host' => '8.8.8.8', 'port' => 22,
            'username' => 'fixture', 'auth_method' => 'password', 'pinned_host_key' => $this->hostKey(),
            'route_mode' => $mode, 'reverse_listener_port' => $port, 'reverse_tunnel_identity' => $identity,
            'binding_revision' => $identityEpoch,
        ]);
        // Exact released v1 envelope and Job identity construction.
        $parts = [$id, $slug, '8.8.8.8', '22', 'fixture', 'password', $this->hostKey()];
        if ($identityEpoch > 0 || $mode !== 'direct') {
            $parts = [...$parts, $mode, (string) $port, (string) $identity, (string) $identityEpoch];
        }
        if ($epoch > 0 || $relay !== null) {
            $parts = [...$parts, 'connection_relay', (string) $relay, (string) $epoch];
        }
        $digest = hash('sha256', implode("\0", $parts));
        DB::table('target_credentials')->insert([
            'id' => $credential, 'target_record_id' => $id, 'connector_type' => 'ssh_direct', 'purpose' => 'ssh_auth',
            'encrypted_payload' => Crypt::encryptString(json_encode([
                'v' => 1, 'target_record_id' => $id, 'target_id' => $slug, 'connector_type' => 'ssh_direct',
                'purpose' => 'ssh_auth', 'auth_method' => 'password', 'binding' => $digest,
                'secret' => self::SECRET, 'passphrase' => null,
            ], JSON_THROW_ON_ERROR)),
        ]);

        return ['id' => $id, 'credential' => $credential, 'epoch' => $epoch,
            'kind' => $relay !== null ? 'relay' : $mode, 'port' => $port, 'digest' => $digest];
    }

    private function hostKey(): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32));
    }
}
