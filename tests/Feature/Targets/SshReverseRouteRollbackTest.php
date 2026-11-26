<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

final class SshReverseRouteRollbackTest extends TestCase
{
    use RefreshDatabase;

    private const MIGRATION = 'migrations/0001_01_01_000001_create_gateway_v3_schema.php';

    private const SECRET = 'rollback-secret-fixture';

    public function test_v3_untouched_direct_target_cannot_downgrade_and_strand_credentials(): void
    {
        $target = $this->register('fresh-v3-direct');
        $config = SshTargetConfig::query()->sole();
        $ciphertext = TargetCredential::query()->sole()->encrypted_payload;
        self::assertSame(0, $config->binding_revision);
        self::assertSame(self::SECRET, $this->secret($target));

        $this->assertRefusedWithoutMutation($target);

        self::assertSame($ciphertext, TargetCredential::query()->sole()->encrypted_payload);
        self::assertSame(0, SshTargetConfig::query()->sole()->binding_revision);
        self::assertSame(self::SECRET, $this->secret($target));
    }

    public function test_reconfigured_direct_target_refuses_downgrade_and_preserves_ciphertext(): void
    {
        $target = $this->register('updated-direct');
        $original = TargetCredential::query()->sole()->encrypted_payload;
        $service = app(SshTargetReconfiguration::class);
        self::assertTrue($service->update($target, $this->input($target, 'direct', '8.8.4.4')));

        $config = SshTargetConfig::query()->sole();
        self::assertSame('direct', $target->fresh()->transportKind());
        self::assertSame(1, $config->binding_revision);
        self::assertNotSame($original, TargetCredential::query()->sole()->encrypted_payload);
        self::assertSame(0, DB::table('ssh_command_jobs')->count());

        $this->assertRefusedWithoutMutation($target);
    }

    public function test_active_reverse_target_refuses_downgrade_even_at_revision_zero(): void
    {
        $this->approveRoute();
        $target = $this->register('rollback-route', 'reverse');
        self::assertSame(0, SshTargetConfig::query()->sole()->binding_revision);
        self::assertSame('reverse', $target->fresh()->transportKind());

        $this->assertRefusedWithoutMutation($target);
    }

    public function test_retained_ssh_job_refuses_downgrade_even_for_untouched_direct_target(): void
    {
        $target = $this->register('job-direct');
        DB::table('ssh_command_jobs')->insert([
            'id' => (string) Str::ulid(),
            'target_record_id' => $target->getKey(),
            'user_id' => null,
            'client_identity_hash' => hash('sha256', 'rollback-client'),
            'request_id' => (string) Str::uuid(),
            'script_digest' => hash('sha256', 'rollback-script'),
            'target_binding_hash' => SshTargetBinding::hash($target, SshTargetConfig::query()->sole()),
            'status' => 'unsupported',
            'runtime_seconds' => 15,
            'expires_at' => now()->addDay(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());

        $this->assertRefusedWithoutMutation($target);
        self::assertSame(1, DB::table('ssh_command_jobs')->count());
    }

    public function test_direct_reverse_direct_rotation_keeps_positive_epoch_and_blocks_downgrade(): void
    {
        $target = $this->register('rollback-route');
        $service = app(SshTargetReconfiguration::class);
        $originalJobBinding = SshTargetBinding::hash($target, SshTargetConfig::query()->sole());
        $this->approveRoute();

        self::assertTrue($service->update($target, $this->input($target, 'reverse', '8.8.8.8')));
        self::assertSame(1, $target->fresh()->transport_revision);
        $target->refresh();
        self::assertTrue($service->update($target, $this->input($target, 'direct', '8.8.8.8')));

        $config = SshTargetConfig::query()->sole();
        self::assertSame('direct', $target->fresh()->transportKind());
        $target->refresh();
        self::assertSame(2, $target->transport_revision);
        self::assertSame(0, $config->binding_revision);
        self::assertNotSame($originalJobBinding, SshTargetBinding::hash($target, $config));
        self::assertSame(0, DB::table('ssh_command_jobs')->count());

        $this->assertRefusedWithoutMutation($target);
    }

    private function assertRefusedWithoutMutation(Target $target): void
    {
        $configBefore = SshTargetConfig::query()->sole()->getAttributes();
        $cipherBefore = TargetCredential::query()->sole()->encrypted_payload;
        self::assertSame(self::SECRET, $this->secret($target));

        $refused = false;
        try {
            $this->migration()->down();
        } catch (RuntimeException $exception) {
            $refused = true;
            self::assertStringContainsString('do not roll back the gateway v3 baseline', strtolower($exception->getMessage()));
        }
        self::assertTrue($refused, 'Gateway v3 baseline rollback must always refuse before dropping binding columns.');

        foreach (['transport_revision', 'reverse_listener_port', 'reverse_tunnel_identity'] as $column) {
            self::assertTrue(Schema::hasColumn('targets', $column), $column);
        }
        self::assertTrue(Schema::hasColumn('ssh_direct_target_configs', 'binding_revision'));
        self::assertSame($configBefore, SshTargetConfig::query()->sole()->getAttributes());
        self::assertSame($cipherBefore, TargetCredential::query()->sole()->encrypted_payload);
        self::assertSame(self::SECRET, $this->secret($target),
            'A rejected migration leaves the still-valid encrypted credential readable.');
    }

    private function migration(): Migration
    {
        return require database_path(self::MIGRATION);
    }

    private function register(string $targetId, string $mode = 'direct'): Target
    {
        return app(SshTargetRegistration::class)->register(
            $targetId, 'Rollback test', '8.8.8.8', 22, 'deploy',
            $this->hostKey(), 'password', self::SECRET, null,
            null, $mode, $mode === 'reverse' ? 62341 : null,
            $mode === 'reverse' ? 'rollback-operator' : null,
        );
    }

    private function approveRoute(): void
    {
        config()->set('ssh.reverse_approved_routes', json_encode([
            'rollback-route' => ['port' => 62341, 'tunnel_identity' => 'rollback-operator'],
        ], JSON_THROW_ON_ERROR));
    }

    /** @return array<string, string|int|null> */
    private function input(Target $target, string $mode, string $host): array
    {
        return [
            'configuration_revision' => app(SshTargetReconfiguration::class)->revision($target),
            'ssh_host' => $host,
            'ssh_port' => 22,
            'ssh_username' => 'deploy',
            'ssh_host_key' => $this->hostKey(),
            'ssh_auth_method' => 'password',
            'ssh_trust_confirmed' => 'yes',
            'ssh_route_mode' => $mode,
            'ssh_reverse_port' => $mode === 'reverse' ? 62341 : null,
            'ssh_tunnel_identity' => $mode === 'reverse' ? 'rollback-operator' : null,
        ];
    }

    private function secret(Target $target): string
    {
        return app(SshTargetVault::class)->open(
            $target, SshTargetConfig::query()->sole(), TargetCredential::query()->sole(),
        )['secret'];
    }

    private function hostKey(): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat("\x33", 32));
    }
}
