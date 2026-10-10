<?php

namespace Tests\Feature\Targets;

use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetRegistration;
use App\Application\Targets\SshVerificationState;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
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

    public function test_public_egress_failure_flows_through_claim_and_fenced_failure_commit(): void
    {
        [$target, $config] = $this->registered();
        try {
            app(SshTargetConnectionService::class)->test($target);
            self::fail('Loopback must be rejected by production SSH address policy.');
        } catch (SshTargetConnectionException $exception) {
            self::assertSame('egress_denied', $exception->reason);
        }

        self::assertSame('error', $target->fresh()->connection_state->value);
        self::assertSame('egress_denied', $target->fresh()->last_error_code);
        self::assertNull($config->fresh()->verification_attempt_id);
        self::assertSame(1, DB::table('activity_events')->where('operation', 'ssh-login-verify')
            ->where('error_code', 'egress_denied')->count());
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
