<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseInstallCommand;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use InvalidArgumentException;
use RuntimeException;
use Tests\TestCase;

final class SshManagedReverseEnrollmentTest extends TestCase
{
    use RefreshDatabase;

    private string $keyFile;

    private string $manifestFile;

    protected function setUp(): void
    {
        parent::setUp();
        $dir = storage_path('framework/testing/ssh-reverse-'.bin2hex(random_bytes(8)));
        File::ensureDirectoryExists($dir, 0700);
        $this->keyFile = $dir.'/authorized_keys';
        $this->manifestFile = $dir.'/manifest.json';
        config()->set('ssh.managed_reverse.authorized_keys_file', $this->keyFile);
        config()->set('ssh.managed_reverse.host_manifest_file', $this->manifestFile);
        config()->set('ssh.reverse_approved_routes', '{}');
    }

    protected function tearDown(): void
    {
        File::deleteDirectory(dirname($this->keyFile));
        parent::tearDown();
    }

    private function gateway(bool $enabled = true): void
    {
        file_put_contents($this->manifestFile, json_encode([
            'version' => 1,
            'control_port' => 7770,
            'control_user' => 'mcp-reverse',
            'control_host_key' => $this->publicKey(41),
            'authorized_keys_file' => $this->keyFile,
        ], JSON_THROW_ON_ERROR));
        SshManagedReverseGateway::query()->create([
            'id' => 1, 'enabled' => $enabled,
            'control_host' => 'control.example.test', 'control_port' => 7770,
            'control_user' => 'mcp-reverse',
            'control_host_key' => $this->publicKey(41),
        ]);
    }

    private function publicKey(int $byte): string
    {
        return 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat(chr($byte), 32));
    }

    private function begin(): array
    {
        return app(SshManagedReverseEnrollmentService::class)->begin(
            'managed-target', 'Managed', '8.8.8.8', 2222, 'deployer', $this->publicKey(52),
        );
    }

    public function test_feature_is_off_by_default_and_host_bootstrap_is_required(): void
    {
        $this->expectException(RuntimeException::class);
        $this->begin();
    }

    public function test_missing_bootstrap_fails_closed_even_when_enabled(): void
    {
        $this->gateway();
        try {
            $this->begin();
            self::fail('Enrollment must not proceed without host bootstrap file.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('bootstrap', $exception->getMessage());
        }
        self::assertSame(0, Target::query()->count());
        self::assertSame(0, SshManagedReverseEnrollment::query()->count());
    }

    public function test_one_use_claim_permissions_key_file_replay_revocation_and_vault(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $row = $started['enrollment'];
        $target = Target::query()->sole();
        $config = SshTargetConfig::query()->sole();
        $credential = TargetCredential::query()->sole();
        self::assertSame('pending', $row->state);
        self::assertSame('pending', $target->connection_state->value);
        self::assertSame('reverse', $config->route_mode);
        self::assertSame('private_key', $config->auth_method);
        self::assertStringNotContainsString($started['token'], json_encode($row->getAttributes()));
        self::assertStringContainsString('BEGIN OPENSSH PRIVATE KEY', app(SshTargetVault::class)
            ->open($target, $config, $credential)['secret']);
        $policy = app(SshReverseRoutePolicy::class);
        try {
            $policy->forTarget($target, $config);
            self::fail('Unclaimed enrollment bypassed the route gate.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('reverse_route_not_approved', $exception->reason);
        }

        $claimed = app(SshManagedReverseEnrollmentService::class)->claim(
            $row->id, $started['token'], $this->publicKey(61),
        );
        self::assertSame('control.example.test', $claimed['control_host']);
        self::assertSame(7770, $claimed['control_port']);
        self::assertSame(2222, $claimed['target_port']);
        self::assertSame('active', $row->fresh()->state);
        self::assertNull($row->fresh()->token_hash);
        $file = file_get_contents($this->keyFile);
        self::assertStringContainsString('restrict,port-forwarding,permitlisten="127.0.0.1:', $file);
        self::assertStringContainsString($this->publicKey(61), $file);
        self::assertStringNotContainsString($started['token'], $file);
        self::assertSame($config->reverse_listener_port, $policy->forTarget($target, $config)->listenerPort);
        $this->expectException(InvalidArgumentException::class);
        app(SshManagedReverseEnrollmentService::class)->claim($row->id, $started['token'], $this->publicKey(61));
    }

    public function test_revoke_removes_authorized_key_and_fences_transport(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        app(SshManagedReverseEnrollmentService::class)->revoke($started['enrollment']);
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertSame('revoked', $started['enrollment']->fresh()->state);
        $this->expectException(SshTargetConnectionException::class);
        app(SshReverseRoutePolicy::class)->forTarget(Target::query()->sole(), SshTargetConfig::query()->sole());
    }

    public function test_pending_managed_route_never_degrades_to_direct_after_configuration_drift(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $target = $started['enrollment']->target;
        $config = $target->sshConfig;
        // Simulate a privileged schema/data drift that bypasses the form.
        DB::table('ssh_direct_target_configs')
            ->where('id', $config->getKey())
            ->update([
                'route_mode' => 'direct',
                'reverse_listener_port' => null,
                'reverse_tunnel_identity' => null,
            ]);
        try {
            app(SshReverseRoutePolicy::class)->forTarget($target, $config->fresh());
            self::fail('Live managed authorization unexpectedly permitted Direct fallback.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('reverse_route_not_approved', $e->reason);
        }
    }

    public function test_direct_service_disconnect_cannot_orphan_managed_control_authority(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $target = $started['enrollment']->target;
        try {
            app(SshTargetConnectionService::class)->disconnect($target);
            self::fail('Direct credential disconnect removed a live managed binding.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('reverse_route_not_approved', $e->reason);
        }
        self::assertSame(1, TargetCredential::query()
            ->where('target_record_id', $target->getKey())->count());
    }

    public function test_failed_first_verify_preserves_pending_setup_with_diagnostics(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $target = $started['enrollment']->target;

        try {
            app(SshTargetConnectionService::class)->test($target);
            self::fail('Unclaimed managed tunnel was unexpectedly verified.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('reverse_route_not_approved', $e->reason);
        }
        $reloaded = $target->fresh();
        self::assertSame('pending', $reloaded->connection_state->value);
        self::assertSame('reverse_route_not_approved', $reloaded->last_error_code);
        self::assertSame('reverse_route_not_approved', $reloaded->last_failure_code);
        self::assertNotNull($reloaded->last_tested_at);
    }

    public function test_active_managed_enrollment_cannot_be_silently_reconfigured_to_direct(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $target = $started['enrollment']->target;
        $configuration = app(SshTargetReconfiguration::class);
        $revision = $configuration->revision($target);

        try {
            $configuration->update($target, [
                'configuration_revision' => $revision,
                'ssh_host' => '8.8.8.8',
                'ssh_port' => 2222,
                'ssh_username' => 'deployer',
                'ssh_host_key' => $this->publicKey(52),
                'ssh_trust_confirmed' => 'yes',
                'ssh_auth_method' => 'private_key',
                'ssh_private_key' => null,
                'ssh_password' => null,
                'ssh_passphrase' => null,
                'ssh_route_mode' => 'direct',
                'ssh_reverse_port' => null,
                'ssh_tunnel_identity' => null,
            ]);
            self::fail('Managed listener was silently changed to Direct.');
        } catch (TargetConnectorFailure $e) {
            self::assertSame('managed_reverse_reconfiguration_requires_revocation', $e->reason);
        }

        self::assertSame('reverse', $target->sshConfig->fresh()->route_mode);
        self::assertSame('pending', $started['enrollment']->fresh()->state);
        self::assertSame(1, TargetCredential::query()
            ->where('target_record_id', $target->getKey())->count());
    }

    public function test_enrollment_uses_the_lowercase_laravel_ulid_accepted_by_target_installer(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        config()->set('app.url', 'https://gateway.example.test');
        $started = $this->begin();
        $id = (string) $started['enrollment']->getKey();
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/D', $id);

        $command = app(SshManagedReverseInstallCommand::class)
            ->command($started['enrollment'], $started['token']);
        self::assertStringContainsString($id, $command);
        self::assertStringContainsString('--enrollment', $command);
    }

    public function test_one_control_public_key_cannot_be_claimed_for_two_targets(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $first = $this->begin();
        $second = app(SshManagedReverseEnrollmentService::class)->begin(
            'second-target', 'Second', '8.8.4.4', 22, 'deployer', $this->publicKey(52),
        );
        $service = app(SshManagedReverseEnrollmentService::class);
        $service->claim($first['enrollment']->id, $first['token'], $this->publicKey(61));
        $this->expectException(InvalidArgumentException::class);
        $service->claim($second['enrollment']->id, $second['token'], $this->publicKey(61));
    }

    public function test_duplicate_target_is_not_registered_and_invalid_key_does_not_consume_token(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        try {
            $this->begin();
            self::fail('Duplicate Target was accepted.');
        } catch (InvalidArgumentException) {
            self::assertSame(1, Target::query()->count());
        }
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $started['enrollment']->id, $started['token'], 'ssh-ed25519 invalid',
            );
            self::fail('Malformed key accepted.');
        } catch (InvalidArgumentException) {
            self::assertSame('pending', $started['enrollment']->fresh()->state);
        }
    }
}
