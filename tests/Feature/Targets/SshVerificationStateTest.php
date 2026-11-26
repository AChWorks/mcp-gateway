<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\SshVerificationState;
use App\Application\Targets\TargetInventory;
use App\Application\Targets\TargetTransportBinding;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Connectors\SshDirect\SshTargetIdentity;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-concurrency')]
final class SshVerificationStateTest extends TestCase
{
    use RefreshDatabase;

    public function test_delayed_old_success_cannot_overwrite_newer_failure_after_lease_expiry(): void
    {
        [$target, $config, $credential] = $this->registered();
        $state = app(SshVerificationState::class);

        // Barrier: older worker finished authentication, but its DB commit
        // is held until after a newer admitted attempt commits its failure.
        $old = $state->begin($target, $config, $credential);
        $oldCommit = static fn () => $state->succeeded($target, $config, $credential, $old, '8.8.8.8');
        $new = $state->begin($target, $config, $credential);
        self::assertNotSame($old, $new);
        $state->failed($target, $config, $credential, $new, 'authentication_failed');

        try {
            $oldCommit();
            self::fail('A superseded successful SSH attempt must not commit.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('verification_superseded', $exception->reason);
        }

        $target->refresh();
        self::assertSame('error', $target->connection_state->value);
        self::assertSame('authentication_failed', $target->last_error_code);
        self::assertNull($target->last_success_at);
        self::assertNotNull($target->last_failure_at);
        self::assertNull($config->fresh()->observed_peer_ip);
        self::assertNull($config->fresh()->verification_attempt_id);
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-login-verify')
            ->where('outcome', 'failure')->count());
        self::assertSame(0, DB::table('activity_events')->where('operation', 'ssh-login-verify')
            ->where('outcome', 'success')->count());
    }

    public function test_delayed_old_failure_cannot_overwrite_newer_success_after_lease_expiry(): void
    {
        [$target, $config, $credential] = $this->registered();
        $state = app(SshVerificationState::class);

        // Reverse barrier: an older failed transport reports only after a
        // newer successful authentication has persisted its actual peer.
        $old = $state->begin($target, $config, $credential);
        $oldCommit = static fn () => $state->failed($target, $config, $credential, $old, 'tcp_unreachable');
        $new = $state->begin($target, $config, $credential);
        $state->succeeded($target, $config, $credential, $new, '8.8.8.8');
        $oldCommit();

        $target->refresh();
        self::assertSame('connected', $target->connection_state->value);
        self::assertNull($target->last_error_code);
        self::assertNotNull($target->last_success_at);
        self::assertNull($target->last_failure_at);
        self::assertSame('8.8.8.8', $config->fresh()->observed_peer_ip);
        self::assertNull($config->fresh()->verification_attempt_id);
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-login-verify')
            ->where('outcome', 'success')->count());
        self::assertSame(0, DB::table('activity_events')->where('operation', 'ssh-login-verify')
            ->where('outcome', 'failure')->count());
    }

    public function test_disconnect_invalidates_in_flight_attempt_and_prevents_state_resurrection(): void
    {
        [$target, $config, $credential] = $this->registered();
        $state = app(SshVerificationState::class);
        $attempt = $state->begin($target, $config, $credential);
        self::assertSame($attempt, $config->fresh()->verification_attempt_id);

        app(SshTargetConnectionService::class)->disconnect($target);
        $state->failed($target, $config, $credential, $attempt, 'authentication_failed');
        try {
            $state->succeeded($target, $config, $credential, $attempt, '8.8.8.8');
            self::fail('Disconnected SSH credentials must not be resurrected.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }

        self::assertSame('disconnected', $target->fresh()->connection_state->value);
        self::assertNull($config->fresh()->verification_attempt_id);
        self::assertNull($config->fresh()->observed_peer_ip);
        self::assertSame(0, TargetCredential::query()->count());
        self::assertSame(0, DB::table('activity_events')->where('operation', 'ssh-login-verify')->count());
    }

    public function test_same_ciphertext_superseded_grant_cannot_commit_old_verify(): void
    {
        [$target, $config, $credential] = $this->registered();
        $state = app(SshVerificationState::class);
        $attempt = $state->begin($target, $config, $credential);
        $material = $credential->materialFingerprint();
        DB::transaction(function () use ($target, $credential): void {
            Target::query()->whereKey($target->getKey())->lockForUpdate()->sole();
            $credential->fresh()->supersedeAuthority();
        });
        self::assertSame($material, $credential->fresh()->materialFingerprint());
        self::assertNotSame($credential->authorityFingerprint(), $credential->fresh()->authorityFingerprint());
        try {
            $state->succeeded($target, $config, $credential, $attempt, '8.8.8.8');
            self::fail('Superseded grant cannot commit a successful Verify.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('target_changed', $exception->reason);
        }
        $state->failed($target, $config, $credential, $attempt, 'authentication_failed');
        self::assertNull($target->fresh()->last_tested_at);
        $fresh = $credential->fresh();
        $new = $state->begin($target, $config->fresh(), $fresh);
        $state->succeeded($target, $config->fresh(), $fresh, $new, '8.8.8.8');
        self::assertSame('connected', $target->fresh()->connection_state->value);
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-login-verify')->count());
    }

    public function test_public_egress_failure_flows_through_claim_and_fenced_failure_commit(): void
    {
        [$target, $config] = $this->registered();
        try {
            app(SshTargetConnectionService::class)->test($target);
            self::fail('Loopback must be rejected by production SSH address policy.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('egress_denied', $exception->reason);
            self::assertSame('literal', $exception->diagnostics['outbound_address_source'] ?? null);
            self::assertSame('127.0.0.1', $exception->diagnostics['outbound_rejected_address'] ?? null);
            self::assertSame('admission', $exception->diagnostics['failure_stage'] ?? null);
        }

        self::assertSame('error', $target->fresh()->connection_state->value);
        self::assertSame('egress_denied', $target->fresh()->last_error_code);
        self::assertNull($config->fresh()->verification_attempt_id);
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-login-verify')
            ->where('error_code', 'egress_denied')->count());
    }

    public function test_route_change_and_later_reverse_failure_do_not_report_old_peer_as_current(): void
    {
        [$target, $config, $credential] = $this->registered();
        $state = app(SshVerificationState::class);
        $attempt = $state->begin($target, $config, $credential);
        $state->succeeded($target, $config, $credential, $attempt, '8.8.8.8');
        $target->refresh();
        $user = User::query()->create([
            'name' => 'Fixture owner', 'email' => 'route-owner@example.test', 'password' => 'FixtureOwner!234',
            'role' => 'owner', 'target_scope_mode' => 'all', 'access_enabled' => true,
        ]);
        $inventory = app(TargetInventory::class);
        self::assertCount(1, $inventory->mcpPage($user, search: '8.8.8.8')['items']);
        self::assertCount(1, $inventory->adminPage($user, search: '8.8.8.8')['items']);

        DB::transaction(function () use ($target): void {
            $locked = Target::query()->whereKey($target->getKey())->lockForUpdate()->sole();
            app(TargetTransportBinding::class)->changeReverseLocked($locked, 62397, 'fixture-reverse');
        });
        $target->refresh();
        self::assertSame('connected', $target->connection_state->value);
        self::assertCount(0, $inventory->mcpPage($user, search: '8.8.8.8')['items']);
        self::assertCount(0, $inventory->adminPage($user, search: '8.8.8.8')['items']);

        $attempt = $state->begin($target, $config->fresh(), $credential);
        $state->succeeded($target, $config->fresh(), $credential, $attempt, '127.0.0.1');
        $target->refresh();
        self::assertSame('reverse_route_verified', SshTargetIdentity::safeMetadata($target->load('sshConfig'))['ip_status']);
        $attempt = $state->begin($target, $config->fresh(), $credential);
        $state->failed($target, $config->fresh(), $credential, $attempt, 'reverse_listener_unavailable');
        $target->refresh();
        self::assertSame('connected', $target->connection_state->value);
        self::assertSame('reverse_route_stale', SshTargetIdentity::safeMetadata($target->load('sshConfig'))['ip_status']);
    }

    /** @return array{Target, SshTargetConfig, TargetCredential} */
    private function registered(): array
    {
        $type = 'ssh-ed25519';
        $pin = $type.' '.base64_encode(pack('N', 11).$type.pack('N', 32).str_repeat("\x44", 32));
        $target = app(SshTargetRegistration::class)->register(
            'fenced-ssh', 'Fenced SSH', '127.0.0.1', 22, 'deploy',
            $pin, 'password', 'disposable-test-secret', null,
        );

        return [
            $target,
            SshTargetConfig::query()->where('target_record_id', $target->getKey())->sole(),
            TargetCredential::query()->where('target_record_id', $target->getKey())->sole(),
        ];
    }
}
