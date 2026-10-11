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
        self::assertSame('remote_readback_sha256', $write['result']['integrity_check']);
        self::assertMatchesRegularExpression('/^[0-7]{4}$/', $write['result']['published_mode']);
        self::assertSame('127.0.0.1', $write['result']['connected_ip']);

        $stat = $tools->stat($owner, $target->target_id, $path);
        self::assertTrue($stat['ok'], json_encode($stat));
        self::assertSame('file', $stat['result']['file']['type']);
        self::assertSame(4, $stat['result']['file']['size']);
        self::assertSame($write['result']['published_mode'], $stat['result']['file']['mode']);
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

        // An explicit replacement must preserve a previously private mode.
        $chmod = app(SshCommandMcpToolHandlers::class)->run(
            $owner, $target->target_id, 'chmod 600 '.escapeshellarg($path),
        );
        self::assertTrue($chmod['ok'], json_encode($chmod));

        $replacement = "\x00\xfe";
        $replaced = $tools->write($owner, $target->target_id, $path, base64_encode($replacement), true, 4, $mtime);
        self::assertTrue($replaced['ok'], json_encode($replaced));
        self::assertTrue($replaced['result']['overwrote']);
        self::assertSame('posix_replace', $replaced['result']['publish_method']);
        self::assertSame('remote_readback_sha256', $replaced['result']['integrity_check']);
        self::assertSame('0600', $replaced['result']['published_mode']);

        // Optional stale preconditions reject a mismatch, without publishing.
        $stale = $tools->write($owner, $target->target_id, $path, base64_encode('stale'), true, 4, $mtime);
        self::assertFalse($stale['ok']);
        self::assertSame('source_changed', $stale['error']['code']);

        // The common case needs only explicit overwrite=true.
        $simpleReplacement = 'unconditional';
        $simple = $tools->write($owner, $target->target_id, $path, base64_encode($simpleReplacement), true);
        self::assertTrue($simple['ok'], json_encode($simple));
        self::assertTrue($simple['result']['overwrote']);
        self::assertSame('posix_replace', $simple['result']['publish_method']);
        self::assertSame('0600', $simple['result']['published_mode']);

        $final = $tools->read($owner, $target->target_id, $path);
        self::assertTrue($final['ok'], json_encode($final));
        self::assertSame($simpleReplacement, base64_decode($final['result']['data'], true));
        self::assertSame(strlen($simpleReplacement), $final['result']['size']);

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

        $uploaded = $runtime->uploadFromStream($owner, $target, $path, $source, strlen($bytes), $hash, 300000, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'));
        fclose($source);
        self::assertSame('completed', $uploaded['status']);
        self::assertTrue($uploaded['complete']);
        self::assertSame(strlen($bytes), $uploaded['bytes_written']);
        self::assertSame($hash, $uploaded['sha256']);
        self::assertSame('remote_readback_sha256', $uploaded['integrity_check']);
        self::assertSame('exclusive_hardlink', $uploaded['publish_method']);

        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($sink);
        $downloaded = $runtime->downloadToStream($owner, $target, $path, $sink, 300000, 30, $hash);
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
        $replacementHash = hash('sha256', $replacement);
        $source2 = fopen('php://temp', 'w+b');
        self::assertIsResource($source2);
        fwrite($source2, $replacement);
        rewind($source2);

        // The optional condition only checks a known stale version.
        try {
            $runtime->uploadFromStream(
                $owner, $target, $path, $source2, strlen($replacement), $replacementHash,
                250000, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'), true, strlen($bytes) + 1, $mtime,
            );
            self::fail('A stale optional size/mtime precondition should reject.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('source_changed', $e->reason);
        }
        rewind($source2);

        // Explicit overwrite works without requiring any version fields.
        $replaced = $runtime->uploadFromStream(
            $owner, $target, $path, $source2, strlen($replacement), $replacementHash,
            250000, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'), true,
        );
        fclose($source2);
        self::assertSame('completed', $replaced['status']);
        self::assertTrue($replaced['overwrote']);
        self::assertSame('posix_replace', $replaced['publish_method']);
        self::assertSame('0600', $replaced['published_mode']);

        $sink2 = fopen('php://temp', 'w+b');
        self::assertIsResource($sink2);
        $read2 = $runtime->downloadToStream($owner, $target, $path, $sink2, 300000, 30, $replacementHash);
        self::assertSame($replacementHash, $read2['sha256']);
        rewind($sink2);
        self::assertSame($replacement, stream_get_contents($sink2));
        fclose($sink2);
        $after = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path);
        self::assertSame('0600', $after['result']['file']['mode']);
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
            $owner, $target, $path, $source, strlen($bytes), str_repeat('0', 64), 10000, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
        );
        self::assertSame('outcome_unknown', $bad['status']);
        self::assertFalse($bad['complete']);
        self::assertTrue($bad['temporary_cleanup_confirmed']);
        $notPublished = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path);
        self::assertFalse($notPublished['ok']);

        rewind($source);
        $badLength = $runtime->uploadFromStream(
            $owner, $target, $path, $source, strlen($bytes) - 1,
            hash('sha256', substr($bytes, 0, -1)), 10000, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
        );
        self::assertSame('outcome_unknown', $badLength['status']);
        self::assertTrue($badLength['temporary_cleanup_confirmed']);
        $notPublishedAgain = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path);
        self::assertFalse($notPublishedAgain['ok']);
        fclose($source);
    }

    public function test_streamed_upload_rejects_insecure_staging_without_any_write(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $runtime = app(SshFileRuntime::class);
        $path = $this->home().'/private-reject-'.bin2hex(random_bytes(6));
        $bytes = 'sensitive-content';
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, $bytes);
        rewind($source);
        try {
            $runtime->uploadFromStream(
                $owner, $target, $path, $source, strlen($bytes),
                hash('sha256', $bytes), 4096, 30, $this->env('SSH_FIXTURE_INSECURE_STAGING'),
            );
            self::fail('A world-readable staging directory must not be used.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('staging_not_private', $e->reason);
        }
        fclose($source);
        self::assertFalse(app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path)['ok']);
    }

    public function test_streamed_create_only_does_not_clobber_an_existing_destination(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $path = $this->home().'/stream-collision-'.bin2hex(random_bytes(6));
        $existing = app(SshFileMcpToolHandlers::class)->write(
            $owner, $target->target_id, $path, base64_encode('version-B'),
        );
        self::assertTrue($existing['ok']);
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, 'version-A');
        rewind($source);
        try {
            app(SshFileRuntime::class)->uploadFromStream(
                $owner, $target, $path, $source, 9,
                hash('sha256', 'version-A'), 4096, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
            );
            self::fail('Create-only stream cannot replace version B.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('file_exists', $e->reason);
        }
        $read = app(SshFileMcpToolHandlers::class)->read($owner, $target->target_id, $path);
        self::assertTrue($read['ok']);
        self::assertSame('version-B', base64_decode($read['result']['data'], true));

        // Explicit streamed replacement retains the previous published mode.
        rewind($source);
        $replaced = app(SshFileRuntime::class)->uploadFromStream(
            $owner, $target, $path, $source, 9,
            hash('sha256', 'version-A'), 4096, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'), true,
        );
        fclose($source);
        self::assertSame('completed', $replaced['status']);
        self::assertSame('posix_replace', $replaced['publish_method']);
        self::assertSame($existing['result']['published_mode'], $replaced['published_mode']);
        $after = app(SshFileMcpToolHandlers::class)->read($owner, $target->target_id, $path);
        self::assertTrue($after['ok']);
        self::assertSame('version-A', base64_decode($after['result']['data'], true));
    }

    public function test_streamed_internal_adapter_rejects_network_socket_sources_and_sinks(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($pair);
        try {
            try {
                app(SshFileRuntime::class)->downloadToStream(
                    $owner, $target, $this->home().'/file', $pair[0], 4096, 10,
                );
                self::fail('A network sink is not a bounded local staged output file.');
            } catch (SshTargetConnectionException $e) {
                self::assertSame('invalid_input', $e->reason);
            }
            try {
                app(SshFileRuntime::class)->uploadFromStream(
                    $owner, $target, $this->home().'/file', $pair[0], 1,
                    hash('sha256', 'x'), 4096, 10, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
                );
                self::fail('A network source must not be read in the SFTP admission lease.');
            } catch (SshTargetConnectionException $e) {
                self::assertSame('invalid_input', $e->reason);
            }
        } finally {
            fclose($pair[0]);
            fclose($pair[1]);
        }
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
            $runtime->downloadToStream($owner, $target, $path, $sink, 16000, 30);
            self::fail('Expected a typed size limit exception.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('file_too_large', $e->reason);
        }
        self::assertSame(0, ftell($sink));

        try {
            $runtime->downloadToStream($owner, $target, $path, $sink, 20000, 41);
            self::fail('Invalid stream runtime budget must fail before SSH login.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('invalid_input', $e->reason);
        }

        try {
            $runtime->downloadToStream($owner, $target, $path, $sink, 20000, 30, str_repeat('f', 64));
            self::fail('Expected a typed source-integrity exception.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('source_changed', $e->reason);
        }
        rewind($sink);
        self::assertSame($expected, stream_get_contents($sink));
        // Caller must discard this private sink after a failed digest check.
        fclose($sink);
    }

    public function test_internal_streaming_api_denies_revoked_user_before_remote_login(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $owner->access_enabled = false;
        $owner->save();
        $runtime = app(SshFileRuntime::class);
        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($sink);
        try {
            $runtime->downloadToStream(
                $owner, $target, $this->home().'/no-contact-needed',
                $sink, 1024, 30,
            );
            self::fail('Revoked user must not establish a streaming SSH session.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('target_not_found', $e->reason);
        }
        self::assertSame(0, ftell($sink));
        fclose($sink);

        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        try {
            $runtime->uploadFromStream(
                $owner, $target, $this->home().'/no-contact-needed',
                $source, 0, hash('sha256', ''), 1024, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
            );
            self::fail('Revoked user must not upload.');
        } catch (SshTargetConnectionException $e) {
            self::assertSame('target_not_found', $e->reason);
        }
        fclose($source);
    }

    public function test_malicious_sftp_frame_is_rejected_before_dependency_accumulates_it(): void
    {
        $owner = $this->owner();
        $target = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_OVERSIZE'));
        $beforeMemory = memory_get_peak_usage(true);
        $started = microtime(true);

        $result = app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $this->home());

        self::assertFalse($result['ok']);
        self::assertSame('sftp_frame_too_large', $result['error']['code']);
        self::assertLessThan(12, microtime(true) - $started);
        // The hostile endpoint advertises 8 MiB then attempts to send it.
        // Failure occurs on its length header; no 8 MiB SFTP accumulation.
        self::assertLessThan(8 * 1024 * 1024, memory_get_peak_usage(true) - $beforeMemory);
    }

    public function test_multiple_read_batches_support_a_file_larger_than_the_aggregate_buffer_budget(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $path = $this->home().'/multi-batch-'.bin2hex(random_bytes(6));
        $bytes = random_bytes(2 * 1024 * 1024 + 53);
        $hash = hash('sha256', $bytes);
        $source = fopen('php://temp', 'w+b');
        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        self::assertIsResource($sink);
        fwrite($source, $bytes);
        rewind($source);

        try {
            $runtime = app(SshFileRuntime::class);
            $result = $runtime->uploadFromStream(
                $owner, $target, $path, $source, strlen($bytes), $hash,
                3 * 1024 * 1024, 35, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
            );
            self::assertSame('completed', $result['status']);
            $download = $runtime->downloadToStream(
                $owner, $target, $path, $sink, 3 * 1024 * 1024, 35, $hash,
            );
            self::assertSame('completed', $download['status']);
            self::assertSame(strlen($bytes), $download['bytes_read']);
            self::assertSame($hash, $download['sha256']);
            rewind($sink);
            self::assertSame($bytes, stream_get_contents($sink));
        } finally {
            fclose($source);
            fclose($sink);
        }
    }

    public function test_empty_streamed_file_reuses_the_private_zero_byte_inode(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $path = $this->home().'/empty-stream-'.bin2hex(random_bytes(6));
        $source = fopen('php://temp', 'w+b');
        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        self::assertIsResource($sink);
        try {
            $runtime = app(SshFileRuntime::class);
            $uploaded = $runtime->uploadFromStream(
                $owner, $target, $path, $source, 0, hash('sha256', ''),
                4096, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
            );
            self::assertSame('completed', $uploaded['status']);
            self::assertSame('0600', $uploaded['published_mode']);
            $download = $runtime->downloadToStream($owner, $target, $path, $sink, 4096, 30);
            self::assertSame(0, $download['bytes_read']);
            self::assertSame(hash('sha256', ''), $download['sha256']);
        } finally {
            fclose($source);
            fclose($sink);
        }
    }

    public function test_wrong_id_legal_sftp_responses_are_bounded_in_ranged_and_streamed_reads(): void
    {
        $owner = $this->owner();
        $path = $this->home().'/wrong-id-'.bin2hex(random_bytes(6));
        $normal = $this->target('password');
        $created = app(SshFileMcpToolHandlers::class)->write(
            $owner, $normal->target_id, $path, base64_encode(random_bytes(8192)),
        );
        self::assertTrue($created['ok'], json_encode($created));

        $hostile = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_UNEXPECTED_IDS'));
        $before = memory_get_peak_usage(true);
        $result = app(SshFileMcpToolHandlers::class)->read($owner, $hostile->target_id, $path, 0, 8192);
        self::assertFalse($result['ok']);
        self::assertSame('sftp_response_budget_exceeded', $result['error']['code']);
        self::assertLessThan(8 * 1024 * 1024, memory_get_peak_usage(true) - $before);

        $sink = fopen('php://temp', 'w+b');
        self::assertIsResource($sink);
        try {
            $before = memory_get_peak_usage(true);
            try {
                app(SshFileRuntime::class)->downloadToStream(
                    $owner, $hostile, $path, $sink, 16000, 30,
                );
                self::fail('Stream must reject many legal-sized unsolicited response IDs.');
            } catch (SshTargetConnectionException $e) {
                self::assertSame('sftp_response_budget_exceeded', $e->reason);
            }
            self::assertLessThan(8 * 1024 * 1024, memory_get_peak_usage(true) - $before);
            self::assertSame(0, ftell($sink));
        } finally {
            fclose($sink);
        }
    }

    public function test_private_staging_owner_and_pre_first_write_mode_are_verified(): void
    {
        $owner = $this->owner();
        $target = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_WATCH_FIRST_WRITE'));
        $path = $this->home().'/private-observed-'.bin2hex(random_bytes(6));
        $bytes = random_bytes(70000);
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, $bytes);
        rewind($source);
        try {
            $result = app(SshFileRuntime::class)->uploadFromStream(
                $owner, $target, $path, $source, strlen($bytes), hash('sha256', $bytes),
                90000, 30, $this->env('SSH_FIXTURE_WATCH_PRIVATE_STAGING'),
            );
            self::assertSame('completed', $result['status']);
            self::assertSame('0600', $result['published_mode']);
        } finally {
            fclose($source);
        }

        // This proxy records the inode's mode/owner at the very first
        // SFTP WRITE, BEFORE the remote sftp-server processes any data.
        $observed = app(SshCommandMcpToolHandlers::class)->run(
            $owner, $target->target_id,
            'printf "uid=%s " "$(id -u)"; cat ~/.mcp-sftp-first-write-mode',
        );
        self::assertTrue($observed['ok'], json_encode($observed));
        self::assertMatchesRegularExpression(
            '/^uid=([0-9]+) 0600 \1$/D',
            $observed['result']['stdout'],
        );
    }

    public function test_cross_filesystem_exclusive_hardlink_fails_without_rename_fallback(): void
    {
        if (! is_dir('/dev/shm')) {
            self::markTestSkipped('The temporary filesystem /dev/shm is unavailable on this runner.');
        }

        $owner = $this->owner();
        $target = $this->target('password');
        $isDistinct = app(SshCommandMcpToolHandlers::class)->run(
            $owner, $target->target_id,
            'test "$(stat -c %d /dev/shm)" != "$(stat -c %d ~/.mcp-stream-private)"',
        );
        self::assertTrue($isDistinct['ok'], json_encode($isDistinct));
        if (($isDistinct['result']['exit_code'] ?? 1) !== 0) {
            self::markTestSkipped('The runner has no distinct temporary filesystem.');
        }
        $destination = '/dev/shm/.gateway-cross-fs-'.bin2hex(random_bytes(8));
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, 'safe-payload');
        rewind($source);
        try {
            $result = app(SshFileRuntime::class)->uploadFromStream(
                $owner, $target, $destination, $source, 12,
                hash('sha256', 'safe-payload'), 4096, 30,
                $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
            );
            self::assertSame('outcome_unknown', $result['status']);
            self::assertFalse($result['complete']);
            self::assertTrue($result['possible_remote_effect']);
            self::assertFalse(
                app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $destination)['ok'],
            );
        } finally {
            fclose($source);
        }
    }

    public function test_privileged_remote_sftp_rejects_foreign_owned_0700_staging_before_payload(): void
    {
        // Disposable loopback-only SFTP subsystem runs with elevated OS UID
        // while SSH authentication is the fixture user. A foreign user's
        // 0700 directory is accessible to root but NOT confidential from
        // its real owner. The zero-byte probe must detect this mismatch.
        $owner = $this->owner();
        $target = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_ELEVATED_SFTP'));
        // Prove the elevated SFTP subsystem is genuinely reachable and
        // can stat the foreign-owned private directory before fault testing.
        $available = app(SshFileMcpToolHandlers::class)->stat(
            $owner, $target->target_id, $this->env('SSH_FIXTURE_ELEVATED_PRIVATE_STAGING'),
        );
        self::assertTrue($available['ok'], json_encode($available));
        self::assertSame('directory', $available['result']['file']['type']);

        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        $payload = random_bytes(4096);
        fwrite($source, $payload);
        rewind($source);
        $destination = $this->home().'/foreign-owned-privileged-'.bin2hex(random_bytes(6));

        try {
            $result = app(SshFileRuntime::class)->uploadFromStream(
                $owner, $target, $destination, $source, strlen($payload),
                hash('sha256', $payload), 10000, 30,
                $this->env('SSH_FIXTURE_ELEVATED_PRIVATE_STAGING'),
            );
            self::assertSame('outcome_unknown', $result['status']);
            self::assertFalse($result['complete']);
            self::assertFalse(
                app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $destination)['ok'],
            );

            // The directory is owned by the unprivileged login user, but
            // SFTP writes would have occurred as root. No nonzero probe or
            // payload must ever be written into that directory.
            $check = app(SshCommandMcpToolHandlers::class)->run(
                $owner, $target->target_id,
                'test -z "$(find ~/.mcp-stream-elevated-private -maxdepth 1 -type f -size +0c -print -quit)"',
            );
            self::assertTrue($check['ok'], json_encode($check));
            self::assertSame(0, $check['result']['exit_code']);
        } finally {
            fclose($source);
        }
    }

    public function test_foreign_owned_and_symlink_staging_never_receive_sensitive_bytes(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        $bytes = random_bytes(1024);
        $runtime = app(SshFileRuntime::class);
        foreach (['SSH_FIXTURE_FOREIGN_STAGING', 'SSH_FIXTURE_SYMLINK_STAGING', 'SSH_FIXTURE_MISSING_STAGING'] as $stage) {
            $source = fopen('php://temp', 'w+b');
            self::assertIsResource($source);
            fwrite($source, $bytes);
            rewind($source);
            $path = $this->home().'/rejected-stage-'.bin2hex(random_bytes(6));
            try {
                try {
                    $result = $runtime->uploadFromStream(
                        $owner, $target, $path, $source, strlen($bytes),
                        hash('sha256', $bytes), 4096, 30, $this->env($stage),
                    );
                    self::assertSame('outcome_unknown', $result['status']);
                    self::assertFalse($result['complete']);
                } catch (SshTargetConnectionException $e) {
                    self::assertSame('staging_not_private', $e->reason);
                }
            } finally {
                fclose($source);
            }
            self::assertFalse(
                app(SshFileMcpToolHandlers::class)->stat($owner, $target->target_id, $path)['ok'],
                'Rejected staging must never publish the sensitive destination.',
            );
        }
    }

    public function test_delayed_sftp_write_status_obeys_end_to_end_stream_deadline(): void
    {
        $owner = $this->owner();
        $target = $this->target('password', (int) $this->env('SSH_FIXTURE_PORT_DELAY_WRITE'));
        $source = fopen('php://temp', 'w+b');
        self::assertIsResource($source);
        fwrite($source, random_bytes(1024));
        rewind($source);
        $hash = hash('sha256', stream_get_contents($source));
        rewind($source);
        $started = microtime(true);

        $result = app(SshFileRuntime::class)->uploadFromStream(
            $owner, $target, $this->home().'/slow-status-'.bin2hex(random_bytes(6)),
            $source, 1024, $hash, 4096, 7, $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
        );
        fclose($source);
        self::assertSame('outcome_unknown', $result['status']);
        self::assertFalse($result['complete']);
        self::assertTrue($result['possible_remote_effect']);
        self::assertLessThan(15, microtime(true) - $started);

        // SFTP proxy sets a marker only after a real WRITE was received.
        // This distinguishes a real post-dispatch ambiguous result from
        // an operation that failed before any remote mutation.
        $marker = app(SshCommandMcpToolHandlers::class)->run(
            $owner, $target->target_id,
            'test -f ~/.mcp-sftp-delay-write-observed && printf write-observed',
        );
        self::assertTrue($marker['ok'], json_encode($marker));
        self::assertSame('write-observed', $marker['result']['stdout']);
        self::assertSame(0, $marker['result']['exit_code']);
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
