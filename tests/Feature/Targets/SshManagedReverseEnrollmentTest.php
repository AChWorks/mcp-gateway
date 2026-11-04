<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshManagedReverseAuthorizedKeys;
use App\Application\Targets\SshManagedReverseEnrollmentService;
use App\Application\Targets\SshManagedReverseHostReadiness;
use App\Application\Targets\SshManagedReverseInstallCommand;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\TargetConnectorFailure;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use App\Infrastructure\Connectors\SshDirect\SshManagedReverseGateway;
use App\Infrastructure\Connectors\SshDirect\SshReverseRoutePolicy;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetVault;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
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
        // These tests exercise durable enrollment/claim/revoke semantics.
        // A separate readiness matrix tests the real local gate; do not
        // require a privileged OpenSSH daemon for data-layer unit fixtures.
        $ready = \Mockery::mock(SshManagedReverseHostReadiness::class);
        $ready->shouldReceive('assess')->andReturnUsing(static fn ($gateway) => [
            'state' => $gateway?->enabled ? 'Ready' : 'Disabled',
            'reason' => 'Isolated data-layer fixture',
            'external' => 'Not verified',
        ]);
        app()->instance(SshManagedReverseHostReadiness::class, $ready);
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

    public function test_failed_claim_publication_is_durable_and_owner_repair_activates_only_after_publication(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            public bool $fail = true;

            protected function publish(string $contents): void
            {
                if ($this->fail) {
                    throw new RuntimeException('Injected stage/rename publication failure');
                }

                parent::publish($contents);
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $started['enrollment']->id, $started['token'], $this->publicKey(61),
            );
            self::fail('Injected publication failure was hidden.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Injected', $exception->getMessage());
        }
        self::assertSame('claimed', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertFalse($writer->isReconciled());
        try {
            app(SshReverseRoutePolicy::class)->forTarget(
                $started['enrollment']->target, $started['enrollment']->target->sshConfig,
            );
            self::fail('Unpublished claim authorized a route.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('reverse_route_not_approved', $exception->reason);
        }
        $writer->fail = false;
        $writer->sync();
        self::assertSame('active', $started['enrollment']->fresh()->state);
        self::assertFalse($started['enrollment']->fresh()->publication_pending);
        self::assertTrue($writer->isReconciled());
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
    }

    public function test_crash_after_policy_rename_cannot_erase_committed_claim_intent(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            public bool $interrupt = true;

            protected function publish(string $contents): void
            {
                parent::publish($contents);
                if ($this->interrupt) {
                    throw new RuntimeException('Injected interruption after atomic rename');
                }
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $started['enrollment']->id, $started['token'], $this->publicKey(61),
            );
            self::fail('Post-rename interruption was hidden.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('interruption', $exception->getMessage());
        }
        self::assertSame('claimed', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        $this->expectException(InvalidArgumentException::class);
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
    }

    public function test_failed_revocation_publication_still_destroys_credential_and_fences_jobs(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            public bool $fail = true;

            protected function publish(string $contents): void
            {
                if ($this->fail) {
                    throw new RuntimeException('Injected revoke key publication failure');
                }

                parent::publish($contents);
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        $target = $started['enrollment']->target;
        $service = app(SshManagedReverseEnrollmentService::class);
        try {
            $service->revoke($started['enrollment']);
            self::fail('Revocation incorrectly returned complete.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Injected', $exception->getMessage());
        }
        self::assertSame('revoked', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertSame(0, TargetCredential::query()->where('target_record_id', $target->id)->count());
        self::assertSame(1, $target->sshConfig->fresh()->binding_revision);
        self::assertSame(TargetConnectionState::Disconnected, $target->fresh()->connection_state);
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        try {
            app(SshReverseRoutePolicy::class)->forTarget($target, $target->sshConfig->fresh());
            self::fail('Partial host revocation permitted a Gateway SSH operation.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('reverse_route_not_approved', $exception->reason);
        }
        $writer->fail = false;
        $service->revoke($started['enrollment']);
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertFalse($started['enrollment']->fresh()->publication_pending);
        self::assertSame(1, $target->sshConfig->fresh()->binding_revision);
    }

    public function test_expired_or_uncertain_pending_enrollment_can_reissue_with_same_target_and_retired_port(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $oldPort = $started['enrollment']->listener_port;
        $oldTarget = $started['enrollment']->target_record_id;
        $row = $started['enrollment'];
        $vault = app(SshTargetVault::class);
        $target = $row->target;
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
        $originalCiphertext = (string) $credential->encrypted_payload;
        $approvedLogin = $vault->open($target, $target->sshConfig, $credential);
        $row->forceFill(['token_expires_at' => now()->subMinute()])->save();
        $second = app(SshManagedReverseEnrollmentService::class)->reissue($row);
        $reboundCredential = $credential->fresh();
        self::assertNotSame($originalCiphertext, $reboundCredential->encrypted_payload);
        self::assertSame($approvedLogin, $vault->open(
            $target, $target->sshConfig->fresh(), $reboundCredential,
        ));
        self::assertNotSame($row->id, $second['enrollment']->id);
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $second['enrollment']->id);
        self::assertSame($oldTarget, $second['enrollment']->target_record_id);
        self::assertNotSame($oldPort, $second['enrollment']->listener_port);
        self::assertSame(1, DB::table('ssh_reverse_managed_retired_ports')->where('listener_port', $oldPort)->count());
        self::assertSame(1, $row->target->sshConfig->fresh()->binding_revision);
        self::assertSame('pending', $second['enrollment']->state);
        self::assertFalse($second['enrollment']->publication_pending);
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $row->id, $started['token'], $this->publicKey(61),
            );
            self::fail('Old enrollment token was accepted after reissue.');
        } catch (InvalidArgumentException) {
            self::assertSame('pending', $second['enrollment']->fresh()->state);
        }
        app(SshManagedReverseEnrollmentService::class)->claim(
            $second['enrollment']->id, $second['token'], $this->publicKey(62),
        );
        self::assertSame('active', $second['enrollment']->fresh()->state);
        self::assertNull($row->fresh(), 'Previous enrollment ID must not resolve after rotation.');
        self::assertStringContainsString((string) $second['enrollment']->listener_port, file_get_contents($this->keyFile));
        self::assertStringNotContainsString('permitlisten="127.0.0.1:'.$oldPort.'"', file_get_contents($this->keyFile));
    }

    public function test_listener_allocation_skips_an_unrelated_occupied_local_port(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $socket = @stream_socket_server('tcp://127.0.0.1:42000', $errno, $error);
        if (! is_resource($socket)) {
            $this->markTestSkipped('Port 42000 is occupied in this test environment.');
        }
        try {
            $started = $this->begin();
            self::assertNotSame(42000, $started['enrollment']->listener_port);
        } finally {
            fclose($socket);
        }
    }

    public function test_post_publish_database_drift_requires_reconciliation_not_false_activation(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            public bool $drift = true;

            protected function publish(string $contents): void
            {
                parent::publish($contents);
                if ($this->drift) {
                    // Simulate a separate, already committed revocation
                    // between publication and the final DB commit.
                    DB::table('ssh_reverse_managed_enrollments')->update([
                        'state' => 'revoked',
                        'revoked_at' => now(),
                        'publication_pending' => true,
                    ]);
                }
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        try {
            app(SshManagedReverseEnrollmentService::class)->claim(
                $started['enrollment']->id, $started['token'], $this->publicKey(61),
            );
            self::fail('Post-publication intent drift silently activated an enrollment.');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('changed during publication', $e->getMessage());
        }
        self::assertSame('revoked', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));
        try {
            app(SshReverseRoutePolicy::class)->forTarget(
                $started['enrollment']->target, $started['enrollment']->target->sshConfig,
            );
            self::fail('Revoked route stayed authorized after a partial finalization.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('reverse_route_not_approved', $e->reason);
        }
        $writer->drift = false;
        $writer->sync();
        self::assertSame('', file_get_contents($this->keyFile));
        self::assertFalse($started['enrollment']->fresh()->publication_pending);
    }

    public function test_revocation_still_fences_local_authority_if_policy_lock_unavailable(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        // The unprivileged writer has lost access to the policy reader.
        chmod($this->keyFile, 0400);
        try {
            app(SshManagedReverseEnrollmentService::class)->revoke($started['enrollment']);
            self::fail('Unreadable key publication was reported as complete.');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('unavailable', $e->getMessage());
        } finally {
            chmod($this->keyFile, 0600);
        }
        self::assertSame('revoked', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertSame(0, TargetCredential::query()->count());
        self::assertSame(1, $started['enrollment']->target->sshConfig->fresh()->binding_revision);
        app(SshManagedReverseAuthorizedKeys::class)->sync();
        self::assertSame('', file_get_contents($this->keyFile));
    }

    public function test_migration_rollback_preserves_a_revoked_but_unpublished_key_recovery_receipt(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        $writer = new class extends SshManagedReverseAuthorizedKeys
        {
            protected function publish(string $contents): void
            {
                throw new RuntimeException('Injected revocation publication failure');
            }
        };
        app()->instance(SshManagedReverseAuthorizedKeys::class, $writer);
        try {
            app(SshManagedReverseEnrollmentService::class)->revoke($started['enrollment']);
            self::fail('Injected failure must leave a durable reconciliation receipt.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Injected', $exception->getMessage());
        }
        self::assertSame('revoked', $started['enrollment']->fresh()->state);
        self::assertTrue($started['enrollment']->fresh()->publication_pending);
        self::assertStringContainsString($this->publicKey(61), file_get_contents($this->keyFile));

        $migration = require database_path('migrations/2026_11_02_010000_create_managed_reverse_ssh_state.php');
        try {
            $migration->down();
            self::fail('Rollback discarded a pending host-key revocation.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Reconcile pending', $exception->getMessage());
        }
        self::assertTrue(Schema::hasTable('ssh_reverse_managed_enrollments'));
        self::assertTrue(Schema::hasTable('ssh_reverse_gateway_settings'));
    }

    public function test_migration_rollback_refuses_enabled_gateway_or_stale_external_reader(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $migration = require database_path('migrations/2026_11_02_010000_create_managed_reverse_ssh_state.php');
        try {
            $migration->down();
            self::fail('Enabled Gateway configuration was discarded.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('Disable and reconcile', $exception->getMessage());
        }

        SshManagedReverseGateway::query()->whereKey(1)->update(['enabled' => false]);
        file_put_contents($this->keyFile, 'unexpected SSH authorization'.PHP_EOL);
        try {
            $migration->down();
            self::fail('A mismatched authorized_keys reader was discarded.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('reader is empty and reconciled', $exception->getMessage());
        }
        self::assertTrue(Schema::hasTable('ssh_reverse_managed_enrollments'));
    }

    public function test_migration_rollback_refuses_to_forget_retired_listener_ports(): void
    {
        $this->gateway(false);
        file_put_contents($this->keyFile, '');
        DB::table('ssh_reverse_managed_retired_ports')->insert([
            'listener_port' => 42001, 'target_id' => 'retired-target', 'retired_at' => now(),
        ]);
        $migration = require database_path('migrations/2026_11_02_010000_create_managed_reverse_ssh_state.php');
        try {
            $migration->down();
            self::fail('Rollback discarded retired listener quarantine.');
        } catch (RuntimeException $exception) {
            self::assertStringContainsString('retired Reverse SSH listener', $exception->getMessage());
        }
        self::assertTrue(Schema::hasTable('ssh_reverse_managed_retired_ports'));
    }

    public function test_migration_rollback_allows_fresh_unconfigured_installation(): void
    {
        $migration = require database_path('migrations/2026_11_02_010000_create_managed_reverse_ssh_state.php');
        $migration->down();
        try {
            self::assertFalse(Schema::hasTable('ssh_reverse_managed_enrollments'));
            self::assertFalse(Schema::hasTable('ssh_reverse_gateway_settings'));
            self::assertFalse(Schema::hasTable('ssh_reverse_managed_retired_ports'));
        } finally {
            $migration->up();
        }
        self::assertTrue(Schema::hasTable('ssh_reverse_managed_enrollments'));
    }

    public function test_migration_rollback_accepts_fully_reconciled_revocation_after_disable(): void
    {
        $this->gateway();
        file_put_contents($this->keyFile, '');
        $started = $this->begin();
        app(SshManagedReverseEnrollmentService::class)->claim(
            $started['enrollment']->id, $started['token'], $this->publicKey(61),
        );
        app(SshManagedReverseEnrollmentService::class)->revoke($started['enrollment']);
        SshManagedReverseGateway::query()->whereKey(1)->update(['enabled' => false]);
        app(SshManagedReverseAuthorizedKeys::class)->sync();

        self::assertSame('', file_get_contents($this->keyFile));
        self::assertTrue(app(SshManagedReverseAuthorizedKeys::class)->isReconciled());
        self::assertFalse($started['enrollment']->fresh()->publication_pending);

        $migration = require database_path('migrations/2026_11_02_010000_create_managed_reverse_ssh_state.php');
        $migration->down();
        try {
            self::assertFalse(Schema::hasTable('ssh_reverse_managed_enrollments'));
            self::assertFalse(Schema::hasTable('ssh_reverse_gateway_settings'));
            self::assertTrue(Schema::hasTable('targets'), 'Rollback must not destroy unrelated Target records.');
        } finally {
            $migration->up();
        }
        self::assertTrue(Schema::hasTable('ssh_reverse_managed_enrollments'));
    }
}
