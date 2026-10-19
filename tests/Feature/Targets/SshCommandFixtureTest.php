<?php

namespace Tests\Feature\Targets;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/** Actual OpenSSH fixture, loopback-only policy explicitly injected in CI. */
final class SshCommandFixtureTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        if (getenv('SSH_FIXTURE_ENABLED') !== '1') {
            $this->markTestSkipped('Disposable OpenSSH fixture is not configured.');
        }
        $this->app->bind(SshDialAddressPolicy::class, static fn (): SshDialAddressPolicy => new class implements SshDialAddressPolicy
        {
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
            {
                return ['127.0.0.1'];
            }
        });
    }

    public function test_password_command_reports_separate_stdout_stderr_exit_and_verified_peer(): void
    {
        $target = $this->target('password');
        $command = "printf 'normal-out'; printf 'normal-err' >&2; exit 7";
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id, $command);
        self::assertTrue($result['ok'], json_encode($result));
        $data = $result['result'];
        self::assertSame('completed', $data['status']);
        self::assertSame('127.0.0.1', $data['connected_ip']);
        self::assertSame('normal-out', $data['stdout']);
        self::assertSame('normal-err', $data['stderr']);
        self::assertSame('utf-8', $data['stdout_encoding']);
        self::assertSame(7, $data['exit_code']);
        self::assertTrue($data['complete']);
        self::assertFalse($data['truncated']);
        self::assertFalse($data['continuation_available']);
        self::assertStringNotContainsString($command, json_encode(
            DB::table('activity_events')->where('operation', 'ssh-command-run')->get(), JSON_THROW_ON_ERROR,
        ));
    }

    public function test_encrypted_private_key_command_and_binary_stdout_are_preserved(): void
    {
        $target = $this->target('private_key');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id, "printf '\\377\\000'");
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('base64', $result['result']['stdout_encoding']);
        self::assertSame('/wA=', $result['result']['stdout']);
        self::assertSame(2, $result['result']['stdout_bytes']);
        self::assertSame(0, $result['result']['exit_code']);
    }

    public function test_output_flood_drains_safely_and_retains_proven_remote_exit(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 32768 /dev/zero | tr '\\000' x");
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('completed', $result['result']['status']);
        self::assertSame(16384, $result['result']['stdout_bytes']);
        self::assertSame(32768, $result['result']['stdout_total_bytes']);
        self::assertTrue($result['result']['stdout_truncated']);
        self::assertFalse($result['result']['stderr_truncated']);
        self::assertTrue($result['result']['truncated']);
        self::assertTrue($result['result']['complete']);
        self::assertSame(0, $result['result']['exit_code']);
        self::assertFalse($result['result']['continuation_available']);
    }

    public function test_stderr_flood_is_bounded_independently_from_stdout(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 16384 /dev/zero | tr '\\000' e >&2");
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame(8192, $result['result']['stderr_bytes']);
        self::assertSame(16384, $result['result']['stderr_total_bytes']);
        self::assertTrue($result['result']['stderr_truncated']);
        self::assertFalse($result['result']['stdout_truncated']);
        self::assertTrue($result['result']['truncated']);
        self::assertSame(0, $result['result']['exit_code']);
    }

    public function test_multi_megabyte_outputs_are_drained_without_stderr_heap_growth(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id,
            "head -c 2097152 /dev/zero | tr '\\000' s; head -c 2097152 /dev/zero | tr '\\000' e >&2; exit 7");
        self::assertTrue($result['ok'], json_encode($result));
        $data = $result['result'];
        self::assertSame('completed', $data['status']);
        self::assertSame(7, $data['exit_code']);
        self::assertSame(2097152, $data['stdout_total_bytes']);
        self::assertSame(2097152, $data['stderr_total_bytes']);
        self::assertSame(16384, $data['stdout_bytes']);
        self::assertSame(8192, $data['stderr_bytes']);
        self::assertTrue($data['stdout_truncated']);
        self::assertTrue($data['stderr_truncated']);
        self::assertLessThan(128 * 1024 * 1024, memory_get_peak_usage(true));
    }

    public function test_timeout_is_unknown_and_command_is_not_retried(): void
    {
        $target = $this->target('password');
        $result = app(SshCommandMcpToolHandlers::class)->run($this->owner(), $target->target_id, 'sleep 3', 1);
        self::assertFalse($result['ok']);
        self::assertSame('outcome_unknown', $result['error']['code']);
        self::assertFalse($result['result']['complete']);
        self::assertNull($result['result']['exit_code']);
    }

    public function test_disposable_real_ssh_command_runs_longer_than_previous_30_second_ceiling(): void
    {
        $target = $this->target('password');
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_timeout_seconds' => 45,
        ]);
        $result = app(SshCommandMcpToolHandlers::class)->run(
            $this->owner(), $target->target_id, 'sleep 35; printf "after35"; exit 7', 45,
        );
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('completed', $result['result']['status']);
        self::assertSame('after35', $result['result']['stdout']);
        self::assertSame(7, $result['result']['exit_code']);
        self::assertTrue($result['result']['complete']);
    }

    public function test_opt_in_disposable_extended_timeout_acceptance_over_90_or_near_360_seconds(): void
    {
        $seconds = (int) getenv('SSH_COMMAND_EXTENDED_FIXTURE_SECONDS');
        if (! in_array($seconds, [95, 350], true)) {
            $this->markTestSkipped('Set SSH_COMMAND_EXTENDED_FIXTURE_SECONDS=95 or 350 on disposable OpenSSH fixture.');
        }

        $target = $this->target('password');
        $selectedTimeout = $seconds === 350 ? 360 : 120;
        DB::table('operational_settings')->where('id', 1)->update([
            'ssh_command_timeout_seconds' => $selectedTimeout,
        ]);
        $result = app(SshCommandMcpToolHandlers::class)->run(
            $this->owner(), $target->target_id, 'sleep '.$seconds.'; printf "long-ok"', $selectedTimeout,
        );
        self::assertTrue($result['ok'], json_encode($result));
        self::assertSame('completed', $result['result']['status']);
        self::assertSame('long-ok', $result['result']['stdout']);
        self::assertSame(0, $result['result']['exit_code']);
    }

    private function target(string $method): Target
    {
        $secret = $method === 'password'
            ? $this->env('SSH_FIXTURE_PASSWORD')
            : (string) file_get_contents($this->env('SSH_FIXTURE_RSA_LOGIN_KEY'));

        $target = app(SshTargetRegistration::class)->register(
            'ssh-command-'.str_replace('_', '-', $method), 'Command fixture', 'fixture.example.test',
            (int) $this->env('SSH_FIXTURE_PORT_MODERN'), $this->env('SSH_FIXTURE_USER'),
            trim((string) file_get_contents($this->env('SSH_FIXTURE_ED25519_HOST_PUB'))),
            $method, $secret, $method === 'password' ? null : $this->env('SSH_FIXTURE_KEY_PASSPHRASE'),
        );
        // These transport fixtures exercise the command/SFTP data plane.
        // A verified connection is a required test precondition; the real
        // host-key-pinned verify workflow is exercised separately and in
        // installed-mixed E2E. Never relax the production runtime gate.
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'SSH fixture owner',
            'email' => 'fixture-'.uniqid('', true).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function env(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value, 'Missing SSH fixture variable '.$name);
        self::assertNotSame('', $value);

        return $value;
    }
}
