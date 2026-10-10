<?php

namespace Tests\Feature\Targets;

use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshFileMcpToolHandlers;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/** Actual disposable OpenSSH SFTP fixture with an explicit loopback-only policy. */
final class SshFileFixtureTest extends TestCase
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
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint): array
            {
                return ['127.0.0.1'];
            }
        });
    }

    public function test_password_sftp_create_stat_list_ranged_binary_read_and_atomic_replace(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $tools = app(SshFileMcpToolHandlers::class);
        $path = $this->home().'/sftp-'.bin2hex(random_bytes(6)).'.bin';
        $bytes = "\xff\x00AB";

        $write = $tools->write($owner, $target->target_id, $path, base64_encode($bytes));
        self::assertTrue($write['ok'], json_encode($write));
        self::assertSame('completed', $write['result']['status']);
        self::assertSame(strlen($bytes), $write['result']['bytes_written']);
        self::assertTrue($write['result']['atomic_publish']);
        self::assertSame('exclusive_hardlink', $write['result']['publish_method']);
        self::assertSame('127.0.0.1', $write['result']['connected_ip']);

        $stat = $tools->stat($owner, $target->target_id, $path);
        self::assertTrue($stat['ok'], json_encode($stat));
        self::assertSame('file', $stat['result']['file']['type']);
        self::assertSame(4, $stat['result']['file']['size']);
        $mtime = $stat['result']['file']['mtime'];
        self::assertIsInt($mtime);

        $read = $tools->read($owner, $target->target_id, $path, 1, 2, 4, $mtime);
        self::assertTrue($read['ok'], json_encode($read));
        self::assertSame('base64', $read['result']['encoding']);
        self::assertSame("\x00A", base64_decode($read['result']['data'], true));
        self::assertSame(2, $read['result']['length']);
        self::assertFalse($read['result']['end_of_file']);
        self::assertSame('size_mtime_best_effort', $read['result']['source_check']);

        $eof = $tools->read($owner, $target->target_id, $path, 4, 4, 4, $mtime);
        self::assertTrue($eof['ok'], json_encode($eof));
        self::assertSame('', $eof['result']['data']);
        self::assertTrue($eof['result']['end_of_file']);

        $list = $tools->list($owner, $target->target_id, $this->home(), 100);
        self::assertTrue($list['ok'], json_encode($list));
        self::assertTrue($list['result']['complete']);
        self::assertContains(basename($path), array_column($list['result']['items'], 'name'));

        $again = $tools->write($owner, $target->target_id, $path, base64_encode('forbidden'));
        self::assertFalse($again['ok']);
        self::assertSame('file_exists', $again['error']['code']);
        $changed = $tools->read($owner, $target->target_id, $path, 0, 4, 5, $mtime);
        self::assertSame('source_changed', $changed['error']['code']);

        $replacement = "\x00\xfe";
        $replaced = $tools->write($owner, $target->target_id, $path, base64_encode($replacement), true, 4, $mtime);
        self::assertTrue($replaced['ok'], json_encode($replaced));
        self::assertTrue($replaced['result']['overwrote']);
        self::assertSame('posix_replace', $replaced['result']['publish_method']);
        $final = $tools->read($owner, $target->target_id, $path);
        self::assertTrue($final['ok'], json_encode($final));
        self::assertSame($replacement, base64_decode($final['result']['data'], true));
        self::assertSame(2, $final['result']['size']);

        $activity = (string) json_encode(DB::table('activity_events')->where('operation', 'like', 'ssh-file-%')->get(), JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString($path, $activity);
        self::assertStringNotContainsString(base64_encode($bytes), $activity);
        self::assertStringNotContainsString(base64_encode($replacement), $activity);
    }

    public function test_encrypted_private_key_sftp_binary_roundtrip_and_limited_listing(): void
    {
        $owner = $this->owner();
        $target = $this->target('private_key');
        $tools = app(SshFileMcpToolHandlers::class);
        $path = $this->home().'/sftp-key-'.bin2hex(random_bytes(6));
        $content = "\x00\xffbinary\x00\xfe";
        $created = $tools->write($owner, $target->target_id, $path, base64_encode($content));
        self::assertTrue($created['ok'], json_encode($created));

        $read = $tools->read($owner, $target->target_id, $path, 0, 16384);
        self::assertTrue($read['ok'], json_encode($read));
        self::assertSame($content, base64_decode($read['result']['data'], true));
        self::assertTrue($read['result']['end_of_file']);

        $limited = $tools->list($owner, $target->target_id, $this->home(), 1);
        self::assertFalse($limited['ok']);
        self::assertSame('listing_too_large', $limited['error']['code']);
        self::assertArrayNotHasKey('items', $limited);
    }

    public function test_sftp_subsystem_is_required_and_library_shell_fallback_is_blocked(): void
    {
        $owner = $this->owner();
        $target = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_NO_SFTP'));
        $tools = app(SshFileMcpToolHandlers::class);

        $result = $tools->stat($owner, $target->target_id, $this->home());
        self::assertFalse($result['ok']);
        self::assertSame('sftp_unavailable', $result['error']['code']);

        // The same host can execute explicitly authorized SSH commands:
        // refusing SFTP does not silently grant a hidden shell fallback.
        $command = app(SshCommandMcpToolHandlers::class)->run($owner, $target->target_id, "printf 'command-still-works'");
        self::assertTrue($command['ok'], json_encode($command));
        self::assertSame('command-still-works', $command['result']['stdout']);
    }

    public function test_streamed_binary_transfer_is_larger_than_inline_limit_and_verified_end_to_end(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $runtime = app(SshFileRuntime::class);
        $path = $this->home().'/stream-'.bin2hex(random_bytes(6)).'.bin';
        $bytes = random_bytes(262161);
        $hash = hash('sha256', $bytes);
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, $bytes);
        rewind($source);

        $uploaded = $runtime->uploadFromStream($owner, $target, $path, $source, strlen($bytes), $hash, 300000);
        fclose($source);
        self::assertSame('completed', $uploaded['status']);
        self::assertTrue($uploaded['complete']);
        self::assertSame(strlen($bytes), $uploaded['bytes_written']);
        self::assertSame($hash, $uploaded['sha256']);
        self::assertSame('remote_readback_sha256', $uploaded['integrity_check']);
        self::assertSame('exclusive_hardlink', $uploaded['publish_method']);

        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($sink);
        $downloaded = $runtime->downloadToStream($owner, $target, $path, $sink, 300000, $hash);
        self::assertSame('completed', $downloaded['status']);
        self::assertSame(strlen($bytes), $downloaded['bytes_read']);
        self::assertSame($hash, $downloaded['sha256']);
        self::assertSame('size_mtime_and_sha256', $downloaded['source_check']);
        rewind($sink);
        self::assertSame($bytes, stream_get_contents($sink));
        fclose($sink);

        $stat = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path);
        self::assertTrue($stat['ok']);
        $mtime = $stat['result']['file']['mtime'];

        $replacement = random_bytes(200000);
        $source2 = fopen('php://temp', 'w+b');
        self::assertIsResource($source2);
        fwrite($source2, $replacement);
        rewind($source2);
        $replace = $runtime->uploadFromStream(
            $owner, $target, $path, $source2, strlen($replacement), hash('sha256', $replacement),
            250000, true, strlen($bytes), $mtime,
        );
        fclose($source2);
        self::assertSame('completed', $replace['status']);
        self::assertSame('posix_replace', $replace['publish_method']);
        $sink2 = fopen('php://temp', 'w+b');
        self::assertIsResource($sink2);
        $read2 = $runtime->downloadToStream($owner, $target, $path, $sink2, 250000);
        self::assertSame(hash('sha256', $replacement), $read2['sha256']);
        rewind($sink2);
        self::assertSame($replacement, stream_get_contents($sink2));
        fclose($sink2);
    }

    public function test_streamed_transfer_rejects_wrong_digest_and_size_without_publishing(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $runtime = app(SshFileRuntime::class);
        $path = $this->home().'/stream-reject-'.bin2hex(random_bytes(6)).'.bin';
        $bytes = random_bytes(8193);
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, $bytes);
        rewind($source);

        $bad = $runtime->uploadFromStream(
            $owner, $target, $path, $source, strlen($bytes), str_repeat('0', 64), 10000,
        );
        self::assertSame('outcome_unknown', $bad['status']);
        self::assertFalse($bad['complete']);
        self::assertTrue($bad['temporary_cleanup_confirmed']);
        $notPublished = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path);
        self::assertFalse($notPublished['ok']);

        rewind($source);
        $badLength = $runtime->uploadFromStream(
            $owner, $target, $path, $source, strlen($bytes) - 1,
            hash('sha256', substr($bytes, 0, -1)), 10000,
        );
        self::assertSame('outcome_unknown', $badLength['status']);
        self::assertTrue($badLength['temporary_cleanup_confirmed']);
        $notPublishedAgain = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path);
        self::assertFalse($notPublishedAgain['ok']);
        fclose($source);
    }

    public function test_streamed_download_limits_and_hash_mismatch_are_not_silent_success(): void
    {
        $owner = $this->owner();
        $target = $this->target('private_key');
        $runtime = app(SshFileRuntime::class);
        $path = $this->home().'/stream-download-'.bin2hex(random_bytes(6)).'.bin';
        $bytes = random_bytes(25000);
        $created = app(SshFileMcpToolHandlers::class)->write(
            $owner, $target->target_id, $path, base64_encode(substr($bytes, 0, 16384)),
        );
        self::assertTrue($created['ok']);
        $expected = substr($bytes, 0, 16384);

        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($sink);
        try {
            $runtime->downloadToStream($owner, $target, $path, $sink, 16000);
            self::fail('Expected a typed size limit exception.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('file_too_large', $e->reason);
        }
        self::assertSame(0, ftell($sink));

        try {
            $runtime->downloadToStream($owner, $target, $path, $sink, 20000, str_repeat('f', 64));
            self::fail('Expected a typed source-integrity exception.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('source_changed', $e->reason);
        }
        rewind($sink);
        self::assertSame($expected, stream_get_contents($sink));
        // Caller must discard this private sink after a failed digest check.
        fclose($sink);
    }

    private function target(string $method, ?int $port = null): Target
    {
        $secret = $method === 'password'
            ? $this->env('SSH_FIXTURE_PASSWORD')
            : (string) file_get_contents($this->env('SSH_FIXTURE_RSA_LOGIN_KEY'));

        return app(SshTargetRegistration::class)->register(
            'ssh-sftp-'.str_replace('_', '-', $method).($port !== null ? '-no-subsystem' : ''),
            'SFTP fixture', 'fixture.example.test',
            $port ?? (int) $this->env('SSH_FIXTURE_PORT_MODERN'),
            $this->env('SSH_FIXTURE_USER'),
            trim((string) file_get_contents($this->env('SSH_FIXTURE_ED25519_HOST_PUB'))),
            $method, $secret, $method === 'password' ? null : $this->env('SSH_FIXTURE_KEY_PASSPHRASE'),
        );
    }

    private function owner(): User
    {
        return User::query()->create([
            'name' => 'SFTP fixture owner',
            'email' => 'sftp-fixture-'.uniqid('', true).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => 'owner',
            'target_scope_mode' => 'all',
            'access_enabled' => true,
        ]);
    }

    private function home(): string
    {
        return '/home/'.$this->env('SSH_FIXTURE_USER');
    }

    private function env(string $name): string
    {
        $value = getenv($name);
        self::assertIsString($value, 'Missing SSH fixture variable '.$name);
        self::assertNotSame('', $value);

        return $value;
    }
}
