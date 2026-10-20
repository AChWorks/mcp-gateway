<?php

namespace Tests\Feature\Targets;

use App\Application\Access\AccessControl;
use App\Application\Mcp\SshCommandMcpToolHandlers;
use App\Application\Mcp\SshFileMcpToolHandlers;
use App\Application\Mcp\TargetFileInputMcpToolHandlers;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\SshTargetConnectionService;
use App\Application\Targets\SshTargetReconfiguration;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Connectors\SshDirect\SshDialAddressPolicy;
use App\Infrastructure\Connectors\SshDirect\SshRegisteredEndpoint;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use App\Infrastructure\Connectors\SshDirect\SshTargetConfig;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\OAuth\League\Entities\ClientEntity;
use App\Infrastructure\OAuth\League\Entities\ScopeEntity;
use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Infrastructure\OAuth\OAuthAuthorizationStore;
use App\Models\User;
use DateTimeImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\Attributes\DataProvider;
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
            public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array
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

    /** @return array<string, array{string, bool, string}> */
    public static function lateSftpRevocationCases(): array
    {
        return [
            'inline hardlink / direct deny' => ['inline', false, 'direct_deny'],
            'inline rename / Target Pause' => ['inline', true, 'pause'],
            'stream hardlink / group membership removed' => ['stream', false, 'group_removed'],
            'stream rename / global deny' => ['stream', true, 'global_deny'],
        ];
    }

    /** @param 'direct_deny'|'pause'|'global_deny'|'group_removed' $revocation */
    #[DataProvider('lateSftpRevocationCases')]
    public function test_real_sftp_refuses_publication_when_write_rights_change_after_private_staging(
        string $transfer, bool $overwrite, string $revocation,
    ): void {
        $owner = $this->owner();
        $target = $this->target('password');
        $operator = User::query()->create([
            'name' => 'Revocable SFTP operator',
            'email' => 'revocable-sftp-'.bin2hex(random_bytes(7)).'@example.test',
            'password' => 'StrongPassword!234',
            'role' => 'operator',
            'target_scope_mode' => 'selected',
            'access_enabled' => true,
        ]);
        $groupId = null;
        if ($revocation === 'group_removed') {
            $group = TargetGroup::query()->create(['name' => 'Temporary fixture SSH scope']);
            $groupId = $group->getKey();
            DB::table('target_group_users')->insert([
                'target_group_id' => $groupId, 'user_id' => $operator->getKey(),
                'created_at' => now(), 'updated_at' => now(),
            ]);
            DB::table('target_group_targets')->insert([
                'target_group_id' => $groupId, 'target_record_id' => $target->getKey(),
                'created_at' => now(), 'updated_at' => now(),
            ]);
        } else {
            DB::table('user_target_access')->insert([
                'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
                'allowed' => true,
            ]);
        }

        self::assertTrue(app(AccessControl::class)
            ->allows($operator, GatewayPermission::SshFileWrite, $target));
        $path = $this->home().'/late-revoke-'.bin2hex(random_bytes(9));
        $original = 'existing-data-remains-intact';
        if ($overwrite) {
            $initial = app(SshFileRuntime::class)->write($owner, $target, $path, base64_encode($original));
            self::assertSame('completed', $initial['status'], json_encode($initial));
        }

        // Real SFTP session followed by independent SSH filesystem proof.
        // Revoke after the fourth Target-permission SELECT: initial admission,
        // post-login, pre-stage, then pre-payload. The last SELECT has already
        // allowed the staged write. The later hardlink/rename must observe the
        // persisted change, regardless of whether that denial short-circuits
        // before another permission SELECT. No production testing hook.
        $permissionReads = 0;
        $postRevokeTargetReads = 0;
        $revoked = false;
        DB::listen(static function (QueryExecuted $query) use (
            &$permissionReads, &$postRevokeTargetReads, &$revoked, $revocation, $target, $operator, $groupId,
        ): void {
            if (! str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
                return;
            }
            if ($revoked && str_contains($query->sql, 'from "targets"')) {
                $postRevokeTargetReads++;
            }
            if ($revoked || ! str_contains($query->sql, 'user_target_permission_denials')) {
                return;
            }
            $permissionReads++;
            if ($permissionReads !== 4) {
                return;
            }
            $revoked = true;
            match ($revocation) {
                'pause' => DB::table('targets')->where('id', $target->getKey())
                    ->update(['operations_paused' => true]),
                'direct_deny' => DB::table('user_target_permission_denials')->insert([
                    'user_id' => $operator->getKey(), 'target_record_id' => $target->getKey(),
                    'permission' => GatewayPermission::SshFileWrite->value,
                ]),
                'global_deny' => DB::table('user_permission_denials')->insert([
                    'user_id' => $operator->getKey(),
                    'permission' => GatewayPermission::SshFileWrite->value,
                ]),
                'group_removed' => DB::table('target_group_users')
                    ->where('target_group_id', $groupId)
                    ->where('user_id', $operator->getKey())->delete(),
            };
        });

        $payload = 'private-stage-does-not-authorize-publication';
        if ($transfer === 'inline') {
            $result = app(SshFileRuntime::class)->write(
                $operator, $target, $path, base64_encode($payload), $overwrite,
            );
        } else {
            $stream = fopen('php://temp', 'w+b');
            self::assertIsResource($stream);
            fwrite($stream, $payload);
            rewind($stream);
            try {
                $result = app(SshFileRuntime::class)->uploadFromStream(
                    $operator, $target, $path, $stream, strlen($payload), hash('sha256', $payload),
                    4096, 30, $this->env('SSH_FIXTURE_PRIVATE_STAGING'), $overwrite,
                );
            } finally {
                fclose($stream);
            }
        }

        self::assertTrue($revoked, 'The fixture must revoke rights in the authenticated SFTP operation.');
        self::assertSame(4, $permissionReads,
            'Revocation occurs after the pre-payload check; later denies may short-circuit.');
        self::assertGreaterThanOrEqual(1, $postRevokeTargetReads,
            'The fresh Target query must run after revocation, at the final publication boundary.');
        self::assertSame('outcome_unknown', $result['status'], json_encode($result));
        self::assertFalse($result['complete']);

        // A paused Target blocks all fresh operations, including readback;
        // restore only its fixture pause flag before an independent authorized
        // Owner command proves the absence of remote publication.
        if ($revocation === 'pause') {
            DB::table('targets')->where('id', $target->getKey())
                ->update(['operations_paused' => false]);
        }
        $proof = $overwrite
            ? 'test "$(cat '.escapeshellarg($path).')" = '.escapeshellarg($original)
            : 'test ! -e '.escapeshellarg($path);
        $human = app(SshCommandRuntime::class)->run($owner, $target, $proof);
        self::assertSame('completed', $human['status'], json_encode($human));
        self::assertSame(0, $human['exit_code'], json_encode($human));
    }

    /** @return array<string, array{string, bool, string, bool}> */
    public static function supersededSftpConnectionCases(): array
    {
        return [
            'MCP inline hardlink / endpoint and pin' => ['inline', false, 'binding', true],
            'human inline rename / credential reseal' => ['inline', true, 'reseal', false],
            'human stream hardlink / credential replaced' => ['stream', false, 'replace', false],
            'human stream rename / endpoint and pin' => ['stream', true, 'binding', false],
        ];
    }

    #[DataProvider('supersededSftpConnectionCases')]
    public function test_real_sftp_refuses_superseded_connection_after_staging_and_successful_reverification(
        string $transfer, bool $overwrite, string $change, bool $mcp,
    ): void {
        $owner = $this->owner();
        if ($mcp) {
            $owner->forceFill(['ai_access_enabled' => true])->save();
        }
        $target = $this->target('password');
        // Keep independent access to endpoint A after the tested Target moves.
        $proofTarget = $this->target('private_key');
        $config = SshTargetConfig::query()->where('target_record_id', $target->getKey())->firstOrFail();
        $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->firstOrFail();
        $binding = SshTargetBinding::hash($target, $config);
        $directory = $this->home().'/binding-'.bin2hex(random_bytes(9));
        $private = $directory.'/stream';
        $path = $directory.'/destination';
        $original = 'original-destination-must-survive';
        $payload = str_repeat('authenticated-session-payload', $transfer === 'stream' ? 1000 : 1);
        $setup = app(SshCommandRuntime::class)->run(
            $owner, $proofTarget, 'mkdir -m 700 -- '.escapeshellarg($directory).' '.escapeshellarg($private),
        );
        self::assertSame(0, $setup['exit_code'], json_encode($setup));
        if ($overwrite) {
            $initial = app(SshFileRuntime::class)->write($owner, $target, $path, base64_encode($original));
            self::assertSame('completed', $initial['status'], json_encode($initial));
        }
        $bearer = $mcp ? $this->fileMcpBearer($owner) : null;
        $findStage = 'find '.escapeshellarg($directory)
            ." -type f \\( -name payload -o -name '.gateway-stream-*.tmp' \\)";
        $configRead = false;
        $fileChecks = 0;
        $changed = false;
        $reconfigured = false;
        $disconnected = false;
        $reverified = false;
        /** @var bool $finished Read by the retained event listener after this operation returns. */
        $finished = false;
        $verifiedIp = null;
        $zeroProof = null;
        /** @var array<string,mixed>|null $payloadProof Populated by a later query-event callback. */
        $payloadProof = null;

        DB::listen(function (QueryExecuted $query) use (
            &$configRead, &$fileChecks, &$changed, &$reconfigured, &$disconnected, &$reverified,
            &$finished, &$verifiedIp, &$zeroProof, &$payloadProof,
            $target, $proofTarget, $owner, $config, $credential, $change, $findStage,
        ): void {
            $sql = str_replace(['"', chr(96)], '', strtolower($query->sql));
            // Match consecutive config+credential identity reads. Command
            // setup and reverification also read credentials, in a different
            // order; they must not advance the SFTP-boundary counter.
            $fileCheck = $configRead && str_contains($sql, 'from target_credentials where target_credentials.id = ?')
                && (string) ($query->bindings[0] ?? '') === (string) $credential->getKey();
            $configRead = str_contains($sql, 'from ssh_direct_target_configs where ssh_direct_target_configs.id = ?')
                && (string) ($query->bindings[0] ?? '') === (string) $config->getKey();
            if ($finished || ! $fileCheck) {
                return;
            }
            if ($reverified) {
                // One <64 KiB payload has reached private staging. The next
                // guard is immediately before hardlink / POSIX rename.
                $payloadProof = app(SshCommandRuntime::class)->run(
                    $owner, $proofTarget, $findStage." -printf '%s\\n'",
                );

                return;
            }
            if ($changed || ++$fileChecks !== 3) {
                return;
            }
            // Post-login, pre-stage, pre-payload. QueryExecuted fires after
            // this guard's original rows were read. Mutate before returning
            // them, so only the subsequent publication guard sees the change.
            $changed = true;
            $zeroProof = app(SshCommandRuntime::class)->run(
                $owner, $proofTarget, $findStage." -printf '%s %m\\n'",
            );
            if ($change === 'replace') {
                app(SshTargetConnectionService::class)->disconnect($target);
            }
            $reconfiguration = app(SshTargetReconfiguration::class);
            $reconfigured = $reconfiguration->update($target, [
                'configuration_revision' => $reconfiguration->revision($target->fresh()),
                'ssh_host' => $config->host,
                'ssh_port' => $change === 'binding'
                    ? (int) $this->env('SSH_FIXTURE_PORT_WATCH_FIRST_WRITE') : $config->port,
                'ssh_username' => $config->username,
                'ssh_host_key' => $change === 'binding'
                    ? trim((string) file_get_contents($this->env('SSH_FIXTURE_RSA_HOST_PUB'))) : $config->pinned_host_key,
                'ssh_auth_method' => 'password',
                'ssh_password' => $this->env('SSH_FIXTURE_PASSWORD'),
                'ssh_trust_confirmed' => 'yes',
            ]);
            $disconnected = $target->fresh()->getAttribute('connection_state') === TargetConnectionState::Disconnected;
            $verifiedIp = app(SshTargetConnectionService::class)->test($target->fresh());
            $reverified = $target->fresh()->getAttribute('connection_state') === TargetConnectionState::Connected;
        });

        $write = function (string $destination, bool $replace) use (
            $owner, $target, $transfer, $private, $payload, $bearer,
        ): array {
            if ($bearer !== null) {
                return $this->fileWriteOverMcp($bearer, $target->target_id, $destination, $payload, $replace);
            }
            if ($transfer === 'inline') {
                $result = app(SshFileRuntime::class)->write(
                    $owner, $target, $destination, base64_encode($payload), $replace,
                );
            } else {
                $stream = fopen('php://temp', 'w+b');
                self::assertIsResource($stream);
                fwrite($stream, $payload);
                rewind($stream);
                try {
                    $result = app(SshFileRuntime::class)->uploadFromStream(
                        $owner, $target, $destination, $stream, strlen($payload), hash('sha256', $payload),
                        65536, 30, $private, $replace,
                    );
                } finally {
                    fclose($stream);
                }
            }

            return ['ok' => $result['status'] === 'completed', 'result' => $result];
        };
        try {
            $denied = $write($path, $overwrite);
        } finally {
            $finished = true;
        }
        self::assertTrue($changed, json_encode($denied));
        self::assertSame(3, $fileChecks);
        self::assertTrue($reconfigured);
        self::assertTrue($disconnected);
        self::assertSame('127.0.0.1', $verifiedIp);
        self::assertTrue($reverified, 'Rejection must happen after a real successful reconnect.');
        self::assertIsArray($zeroProof);
        self::assertSame(0, $zeroProof['exit_code'], json_encode($zeroProof));
        self::assertSame("0 600\n", $zeroProof['stdout'], 'Private zero-byte staging must precede mutation.');
        self::assertIsArray($payloadProof);
        self::assertSame(0, $payloadProof['exit_code'], json_encode($payloadProof));
        self::assertSame(strlen($payload)."\n", $payloadProof['stdout'],
            'The final publication guard must run after the entire staged payload.');
        self::assertFalse($denied['ok']);
        self::assertSame('outcome_unknown', $denied['result']['status'], json_encode($denied));
        self::assertFalse($denied['result']['complete']);
        self::assertTrue($denied['result']['possible_remote_effect']);

        $current = TargetCredential::query()->where('target_record_id', $target->getKey())->firstOrFail();
        self::assertNotSame($credential->encrypted_payload, $current->encrypted_payload);
        if ($change === 'replace') {
            self::assertNull($credential->fresh());
            self::assertNotSame((string) $credential->getKey(), (string) $current->getKey());
        }
        $currentBinding = SshTargetBinding::hash($target->fresh(), $config->fresh());
        if ($change === 'binding') {
            self::assertNotSame($binding, $currentBinding);
        } else {
            self::assertSame($binding, $currentBinding, 'Credential invalidation is independent of endpoint identity.');
        }

        // Fresh use of the verified Target must still work, with the same
        // valid bearer in the MCP case. Do not change that request's context.
        $fresh = $write($directory.'/fresh', false);
        self::assertTrue($fresh['ok'], json_encode($fresh));
        self::assertSame('completed', $fresh['result']['status']);

        // After all MCP requests, independently inspect endpoint A using the
        // unchanged proof Target and a human request (AI remains off in the
        // human scenarios). No old destination or staging bytes may escape.
        $this->app->instance('request', \Illuminate\Http\Request::create('/admin/targets', 'POST'));
        $destinationProof = $overwrite
            ? 'test "$(cat '.escapeshellarg($path).')" = '.escapeshellarg($original)
            : 'test ! -e '.escapeshellarg($path);
        $proof = app(SshCommandRuntime::class)->run(
            $owner, $proofTarget, $destinationProof.' && '.$findStage.' -print',
        );
        self::assertSame(0, $proof['exit_code'], json_encode($proof));
        self::assertSame('', $proof['stdout'], 'Old staging must be cleaned without publishing.');
        $cleanup = app(SshCommandRuntime::class)->run(
            $owner, $proofTarget,
            'rm -f -- '.escapeshellarg($directory.'/fresh').' '.escapeshellarg($path)
                .' && rmdir -- '.escapeshellarg($private).' '.escapeshellarg($directory),
        );
        self::assertSame(0, $cleanup['exit_code'], json_encode($cleanup));
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
            $runtime->downloadToStream($owner, $target, $path, $sink, 20000, 3601);
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

    public function test_chatgpt_file_param_uses_existing_ssh_sftp_private_atomic_upload_and_hash(): void
    {
        $owner = $this->owner();
        $target = $this->target('password');
        config()->set('ssh.file_transfer.enabled', true);
        config()->set('ssh.file_transfer.max_bytes', 1048576);
        $bytes = str_repeat("\x00\xff\xa1\x7f", 80000);
        $sha256 = hash('sha256', $bytes);
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'files.oaiusercontent.com' ? ['1.1.1.1'] : [];
            }
        });
        Http::preventStrayRequests();
        Http::fake(static fn (Request $request) => Http::response($bytes, 200, [
            'Content-Length' => (string) strlen($bytes),
        ]));
        $path = $this->home().'/chatgpt-file-'.bin2hex(random_bytes(6)).'.bin';
        $input = [
            'download_url' => 'https://files.oaiusercontent.com/private/fixture?sig=opaque',
            'file_id' => 'test-file-id',
            'file_name' => 'fixture.bin',
        ];
        $destination = [
            'path' => $path,
            'private_staging_dir' => $this->env('SSH_FIXTURE_PRIVATE_STAGING'),
        ];
        $result = app(TargetFileInputMcpToolHandlers::class)->receive(
            $owner, $target->target_id, $input, 'ssh_sftp_upload', $destination,
        );
        self::assertTrue($result['ok'], json_encode($result, JSON_THROW_ON_ERROR));
        self::assertSame('verified_ssh_file', $result['state']);
        self::assertSame(strlen($bytes), $result['bytes']);
        self::assertSame($sha256, $result['sha256']);
        self::assertFalse($result['retry_safe']);

        $readback = fopen('php://temp/maxmemory:65536', 'w+b');
        self::assertIsResource($readback);
        try {
            $remote = app(SshFileRuntime::class)->downloadToStream(
                $owner, $target, $path, $readback, 1048576, 30, $sha256,
            );
            self::assertSame(strlen($bytes), $remote['bytes_read']);
            self::assertSame($sha256, $remote['sha256']);
            rewind($readback);
            self::assertSame($bytes, stream_get_contents($readback));
        } finally {
            fclose($readback);
        }

        $again = app(TargetFileInputMcpToolHandlers::class)->receive(
            $owner, $target->target_id, $input, 'ssh_sftp_upload', $destination,
        );
        self::assertFalse($again['ok']);
        self::assertSame('file_exists', $again['error']['code']);
        self::assertFalse($again['error']['retry_safe']);
        Http::assertSent(fn (Request $request) => $request->url() === $input['download_url']);
    }

    private function fileMcpBearer(User $user): string
    {
        Artisan::call('gateway:oauth-keygen', ['--force' => true]);
        $client = (string) config('oauth.client.id');
        $scope = (string) config('oauth.scope');
        app(OAuthAuthorizationStore::class)->approve(
            (int) $user->getKey(), $client, (string) config('oauth.resource'), [$scope],
        );
        $token = app(AccessTokenRepository::class)->getNewToken(
            new ClientEntity($client, 'SFTP binding fixture', []),
            [new ScopeEntity($scope)], (string) $user->getKey(),
        );
        $token->setIdentifier(bin2hex(random_bytes(20)));
        $token->setExpiryDateTime((new DateTimeImmutable)->modify('+15 minutes'));
        $token->setPrivateKey(new CryptKey((string) config('oauth.keys.private')));
        app(AccessTokenRepository::class)->persistNewAccessToken($token);

        return $token->toString();
    }

    /** @return array<string,mixed> */
    private function fileWriteOverMcp(string $bearer, string $targetId, string $path, string $bytes, bool $overwrite): array
    {
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$bearer,
            'Host' => (string) parse_url((string) config('oauth.resource'), PHP_URL_HOST),
            'MCP-Protocol-Version' => '2026-07-28',
            'Mcp-Method' => 'tools/call',
            'Mcp-Name' => 'ssh-file-write',
        ])->postJson('/mcp', [
            'jsonrpc' => '2.0', 'id' => 41, 'method' => 'tools/call',
            'params' => [
                'name' => 'ssh-file-write',
                'arguments' => [
                    'target_id' => $targetId, 'path' => $path,
                    'content_base64' => base64_encode($bytes), 'overwrite' => $overwrite,
                ],
                '_meta' => [
                    'io.modelcontextprotocol/protocolVersion' => '2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities' => (object) [],
                    'io.modelcontextprotocol/clientInfo' => ['name' => 'sftp-binding-fixture', 'version' => '1.0'],
                ],
            ],
        ]);
        self::assertSame(200, $response->getStatusCode());
        $decoded = json_decode($response->streamedContent(), true, flags: JSON_THROW_ON_ERROR);
        $result = $decoded['result']['structuredContent'] ?? null;
        self::assertIsArray($result, json_encode($decoded));

        return $result;
    }

    private function target(string $method, ?int $port = null): Target
    {
        $secret = $method === 'password'
            ? $this->env('SSH_FIXTURE_PASSWORD')
            : (string) file_get_contents($this->env('SSH_FIXTURE_RSA_LOGIN_KEY'));

        $target = app(SshTargetRegistration::class)->register(
            'ssh-sftp-'.str_replace('_', '-', $method).($port !== null ? '-no-subsystem' : ''),
            'SFTP fixture', 'fixture.example.test',
            $port ?? (int) $this->env('SSH_FIXTURE_PORT_MODERN'),
            $this->env('SSH_FIXTURE_USER'),
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
