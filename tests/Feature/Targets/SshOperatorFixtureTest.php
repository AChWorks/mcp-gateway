<?php

namespace Tests\Feature\Targets;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshOperatorMcpToolHandlers;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/** Actual OpenSSH, bound to an isolated loopback fixture on the disposable CI runner. */
final class SshOperatorFixtureTest extends TestCase
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

    public function test_real_system_network_journal_and_sftp_log_observations_are_truthful(): void
    {
        $owner = $this->owner();
        $target = $this->target();
        $tools = app(SshOperatorMcpToolHandlers::class);
        $id = $target->target_id;
        $home = '/home/'.$this->env('SSH_FIXTURE_USER');
        $log = $home.'/gw-op-log-'.bin2hex(random_bytes(8));
        $message = "entry-one\nسلام gateway\nentry-three\n";

        try {
            $written = app(SshFileRuntime::class)->write($owner, $target, $log, base64_encode($message));
            self::assertSame('completed', $written['status'], json_encode($written));

            $system = $tools->system($owner, $id, ['system', 'uptime', 'load', 'memory', 'service'], 'sshd.service');
            self::assertTrue($system['ok'], json_encode($system));
            self::assertSame('observed', $system['result']['status']);
            self::assertSame('seconds', $system['result']['sections']['uptime']['unit']);
            self::assertNotEmpty($system['result']['sections']['system']['lines']);
            self::assertContains($system['result']['sections']['service']['status'], ['observed', 'failed', 'unsupported']);

            $dns = $tools->network($owner, $id, 'dns', 'localhost');
            self::assertTrue($dns['ok'], json_encode($dns));
            self::assertSame('passed', $dns['result']['status']);
            self::assertNotEmpty($dns['result']['observed']['addresses']);

            $tcp = $tools->network($owner, $id, 'tcp', '127.0.0.1', (int) $this->env('SSH_FIXTURE_PORT_MODERN'));
            self::assertContains($tcp['result']['status'] ?? null, ['passed', 'unsupported']);
            self::assertSame('netcat', $tcp['result']['source']);

            $file = $tools->logs($owner, $id, 'file', path: $log, length: 12);
            self::assertTrue($file['ok'], json_encode($file));
            self::assertSame('sftp_file', $file['result']['source']);
            self::assertSame('file_mtime_only; individual log lines unparsed', $file['result']['source_timestamp_quality']);
            self::assertSame(substr($message, 0, 12), base64_decode($file['result']['data'], true));
            self::assertSame(12, $file['result']['next_offset']);
            $rest = $tools->logs($owner, $id, 'file', path: $log, offset: 12, length: 512);
            self::assertTrue($rest['ok'], json_encode($rest));
            self::assertSame(substr($message, 12), base64_decode($rest['result']['data'], true));
            self::assertTrue($rest['result']['end_of_file']);
            self::assertNull($rest['result']['next_offset']);

            $journal = $tools->logs($owner, $id, source: 'journal', service: 'sshd.service', lines: 3);
            // systemd/journald and non-root access vary by actual remote OS;
            // no false assertion that an empty or denied journal is healthy.
            self::assertContains($journal['result']['status'] ?? null, ['observed', 'failed', 'unsupported', 'unknown']);
            self::assertSame('journald', $journal['result']['source']);
            self::assertSame('UTC from journald microsecond timestamps', $journal['result']['source_timezone']);
        } finally {
            $this->command($owner, $target, 'rm -f -- '.escapeshellarg($log));
        }
    }

    public function test_real_service_config_composition_validates_reload_and_independent_health(): void
    {
        $owner = $this->owner();
        $target = $this->target();
        $id = $target->target_id;
        $tools = app(SshOperatorMcpToolHandlers::class);
        $files = app(SshFileRuntime::class);
        $base = '/home/'.$this->env('SSH_FIXTURE_USER').'/gw-op-svc-'.bin2hex(random_bytes(8));
        $config = $base.'.conf';
        $server = $base.'.py';
        $portFile = $base.'.port';
        $pidFile = $base.'.pid';
        $log = $base.'.log';
        $original = "answer=healthy-v1\n";

        try {
            self::assertSame('completed', $files->write($owner, $target, $config, base64_encode($original))['status']);
            self::assertSame('completed', $files->write($owner, $target, $server, base64_encode($this->serviceScript()))['status']);

            // A real disposable Python HTTP fixture is a service-specific
            // command consumer; it is not a new Gateway daemon/agent.
            $launch = 'setsid python3 -u '.escapeshellarg($server).' '.escapeshellarg($config)
                .' '.escapeshellarg($portFile).' > '.escapeshellarg($log).' 2>&1 < /dev/null'
                .' & echo $! > '.escapeshellarg($pidFile)
                .'; i=0; while [ "$i" -lt 40 ]; do if test -s '.escapeshellarg($portFile)
                .'; then exit 0; fi; i=$((i+1)); sleep 0.1; done; exit 9';
            $started = $this->command($owner, $target, $launch);
            self::assertSame(0, $started['exit_code'], json_encode($started));

            $portOutput = $this->command($owner, $target, 'cat -- '.escapeshellarg($portFile));
            $port = (int) trim($portOutput['stdout']);
            self::assertGreaterThan(1023, $port);
            self::assertLessThanOrEqual(65535, $port);

            $healthBefore = $tools->verify($owner, $id, 'http_status', '200',
                host: '127.0.0.1', port: $port, scheme: 'http');
            self::assertTrue($healthBefore['ok'], json_encode($healthBefore));
            self::assertSame('passed', $healthBefore['result']['status']);

            $preview = $tools->patch($owner, $id, $config, 'healthy-v1', 'healthy-v2');
            self::assertTrue($preview['ok'], json_encode($preview));
            self::assertSame('preview', $preview['result']['status']);
            self::assertFalse($preview['result']['remote_mutation']);
            self::assertStringContainsString('-answer=healthy-v1', $preview['result']['diff']['unified']);
            self::assertStringContainsString('+answer=healthy-v2', $preview['result']['diff']['unified']);
            $sha = $preview['result']['baseline_sha256'];
            self::assertSame(hash('sha256', $original), $sha);

            $stale = $tools->patch($owner, $id, $config, 'healthy-v1', 'healthy-v2',
                apply: true, expectedSha256: str_repeat('0', 64));
            self::assertSame('source_changed', $stale['error']['code']);
            $badOccurrence = $tools->patch($owner, $id, $config, 'missing', 'x');
            self::assertSame('patch_match_not_unique', $badOccurrence['error']['code']);

            $applied = $tools->patch($owner, $id, $config, 'healthy-v1', 'healthy-v2',
                apply: true, expectedSha256: $sha);
            self::assertTrue($applied['ok'], json_encode($applied));
            self::assertSame('completed', $applied['result']['status']);
            self::assertTrue($applied['result']['owner_and_mode_verified']);
            self::assertTrue($applied['result']['readback_verified']);
            self::assertFalse($applied['result']['syntax_validated']);
            self::assertFalse($applied['result']['service_reloaded']);
            self::assertNull($applied['result']['service_healthy']);

            // Compose explicitly through existing command + patch + verify:
            // VALIDATE exact updated config BEFORE issuing an authorized HUP.
            $validate = 'python3 '.escapeshellarg($server).' '
                .escapeshellarg($config).' '.escapeshellarg($portFile).' --check';
            self::assertSame(0, $this->command($owner, $target, $validate)['exit_code']);

            $reload = $this->command($owner, $target,
                'kill -HUP -- "$(cat '.escapeshellarg($pidFile).')"');
            self::assertSame(0, $reload['exit_code'], json_encode($reload));

            $afterHash = $tools->verify($owner, $id, 'file_sha256', hash('sha256', "answer=healthy-v2\n"), path: $config,
                before: $sha);
            self::assertTrue($afterHash['ok'], json_encode($afterHash));
            self::assertSame('passed', $afterHash['result']['status']);
            $healthAfter = $tools->verify($owner, $id, 'http_status', '200',
                host: '127.0.0.1', port: $port, scheme: 'http', before: '200');
            self::assertTrue($healthAfter['ok'], json_encode($healthAfter));
            $response = $this->command($owner, $target,
                'curl --fail --silent --max-time 5 -- '.escapeshellarg('http://127.0.0.1:'.$port.'/health'));
            self::assertSame('healthy-v2', trim($response['stdout']));
            self::assertSame(0, $response['exit_code']);

            // Failure path: an intentionally invalid edited config MUST NOT
            // receive reload. The running service stays on the last validated
            // generation; apply of file bytes is not service health proof.
            $badPreview = $tools->patch($owner, $id, $config, 'answer=healthy-v2', 'answer=');
            self::assertTrue($badPreview['ok'], json_encode($badPreview));
            $badApply = $tools->patch($owner, $id, $config, 'answer=healthy-v2', 'answer=',
                apply: true, expectedSha256: $badPreview['result']['baseline_sha256']);
            self::assertTrue($badApply['ok'], json_encode($badApply));
            $validatorFailed = $this->command($owner, $target, $validate);
            self::assertNotSame(0, $validatorFailed['exit_code']);
            // NO reload after rejected validation.
            $stillHealthy = $this->command($owner, $target,
                'curl --fail --silent --max-time 5 -- '.escapeshellarg('http://127.0.0.1:'.$port.'/health'));
            self::assertSame('healthy-v2', trim($stillHealthy['stdout']));

            $repairPreview = $tools->patch($owner, $id, $config, "answer=\n", "answer=healthy-v2\n");
            self::assertTrue($repairPreview['ok'], json_encode($repairPreview));
            $repair = $tools->patch($owner, $id, $config, "answer=\n", "answer=healthy-v2\n",
                apply: true, expectedSha256: $repairPreview['result']['baseline_sha256']);
            self::assertTrue($repair['ok'], json_encode($repair));
            self::assertSame(0, $this->command($owner, $target, $validate)['exit_code']);
        } finally {
            // Only fixture-specific uniquely named files + exact PID created
            // by THIS test. Never stop unrelated system services/processes.
            $cleanup = 'if test -s '.escapeshellarg($pidFile)
                .'; then kill -TERM -- "$(cat '.escapeshellarg($pidFile).')" 2>/dev/null || true; fi; '
                .'rm -f -- '.implode(' ', array_map('escapeshellarg', [
                    $config, $server, $portFile, $pidFile, $log,
                ]));
            $this->command($owner, $target, $cleanup);
        }
    }

    private function serviceScript(): string
    {
        return <<<'PY'
import http.server
import signal
import sys

config, port_path = sys.argv[1:3]

def validated():
    with open(config, encoding="utf-8") as f:
        contents = f.read()
    if not contents.startswith("answer=") or contents.count("\n") != 1 or not contents.endswith("\n"):
        raise ValueError("invalid configuration format")
    value = contents[len("answer="):].strip()
    if not value or len(value) > 128:
        raise ValueError("invalid service response")
    return value

value = validated()
if "--check" in sys.argv:
    sys.exit(0)

def reload_config(*_args):
    global value
    value = validated()

signal.signal(signal.SIGHUP, reload_config)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        data = value.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_path, "w", encoding="ascii") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PY;
    }

    /** @return array<string,mixed> */
    private function command(User $owner, Target $target, string $script): array
    {
        $result = app(SshCommandMcpToolHandlers::class)->run($owner, $target->target_id, $script);
        self::assertTrue($result['ok'], json_encode($result));

        return $result['result'];
    }

    private function target(): Target
    {
        $target = app(SshTargetRegistration::class)->register(
            'ssh-operator-fixture', 'SSH operator fixture', 'fixture.example.test',
            (int) $this->env('SSH_FIXTURE_PORT_MODERN'), $this->env('SSH_FIXTURE_USER'),
            trim((string) file_get_contents($this->env('SSH_FIXTURE_ED25519_HOST_PUB'))),
            'password', $this->env('SSH_FIXTURE_PASSWORD'), null,
        );
        $target->forceFill(['connection_state' => TargetConnectionState::Connected])->save();

        return $target;
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'SSH operator fixture owner',
            'email' => 'ssh-operator-'.uniqid('', true).'@example.test',
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
