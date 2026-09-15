<?php

namespace Tests\Feature\Sites;

use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteCredential;
use App\Domain\Sites\SiteOAuthFlow;
use App\Infrastructure\OAuth\SiteCredentialVault;
use App\Infrastructure\OAuth\SiteOAuthFlowVault;
use DateTimeImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PDO;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('mysql-concurrency')]
final class SiteLifecycleConcurrencyTest extends TestCase
{
    private const CLIENT_ID = 'https://gateway.example.test/oauth/client.json';

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::getDriverName() !== 'mysql') {
            $this->markTestSkipped('MySQL is required for site lifecycle row-lock concurrency validation.');
        }

        config()->set('bridge.client.id', self::CLIENT_ID);
        config()->set('bridge.client.name', 'MCP Gateway Concurrency Test');
        config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/sites/callback');
        config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');

        Artisan::call('migrate:fresh', ['--force' => true]);
        Artisan::call('gateway:bridge-client-keygen', ['--force' => true]);
    }

    public function test_parallel_refreshes_use_only_one_rotating_refresh_token_generation(): void
    {
        $site = $this->connectedSiteWithExpiredCredential();
        [$responses, $logs] = $this->runConcurrentActions($site, [
            ['action' => 'access'],
            ['action' => 'access'],
        ]);

        self::assertCount(2, $responses);
        foreach ($responses as $response) {
            self::assertTrue($response['ok']);
            self::assertSame('rotated-access', $response['access_token'] ?? null);
        }
        self::assertSame(['attempt-1'], $logs['refresh']);

        $credential = $site->refresh()->credential()->firstOrFail();
        $secret = app(SiteCredentialVault::class)->open($credential);
        self::assertSame('rotated-access', $secret->accessToken);
        self::assertSame('rotated-refresh', $secret->refreshToken);
        self::assertSame(SiteConnectionState::Connected, $site->connection_state);
    }

    public function test_refresh_and_disconnect_cannot_resurrect_or_orphan_rotated_credentials(): void
    {
        $site = $this->connectedSiteWithExpiredCredential();
        [$responses, $logs] = $this->runConcurrentActions($site, [
            ['action' => 'access', 'refresh_delay_us' => 500_000],
            ['action' => 'disconnect'],
        ]);

        $disconnect = $this->responseFor($responses, 'disconnect');
        self::assertTrue($disconnect['ok']);
        self::assertFalse($site->refresh()->credential()->exists());
        self::assertSame(SiteConnectionState::Disconnected, $site->connection_state);
        $this->assertEveryIssuedTokenWasRevoked($logs);
    }

    public function test_refresh_and_remove_cannot_leave_a_new_remote_credential_after_site_deletion(): void
    {
        $site = $this->connectedSiteWithExpiredCredential();
        $siteId = (string) $site->getKey();
        [$responses, $logs] = $this->runConcurrentActions($site, [
            ['action' => 'access', 'refresh_delay_us' => 500_000],
            ['action' => 'remove'],
        ]);

        $remove = $this->responseFor($responses, 'remove');
        self::assertTrue($remove['ok']);
        self::assertNull(Site::query()->find($siteId));
        self::assertSame(0, SiteCredential::query()->where('site_record_id', $siteId)->count());
        $this->assertEveryIssuedTokenWasRevoked($logs);
    }

    public function test_concurrent_target_updates_serialize_before_remote_revocation(): void
    {
        $alpha = $this->connectedSiteWithCredential('alpha', 'https://alpha.example.test');
        $beta = $this->connectedSiteWithCredential('beta', 'https://beta.example.test');
        $target = 'https://shared.example.test';

        [$responses, $logs] = $this->runConcurrentActions($alpha, [
            [
                'action' => 'update',
                'site_record_id' => (string) $alpha->getKey(),
                'display_name' => 'Alpha',
                'target_base_url' => $target,
                'revoke_delay_us' => 750_000,
            ],
            [
                'action' => 'update',
                'site_record_id' => (string) $beta->getKey(),
                'display_name' => 'Beta',
                'target_base_url' => $target,
                'revoke_delay_us' => 750_000,
            ],
        ], false);

        $successes = array_values(array_filter($responses, static fn (array $response): bool => $response['ok']));
        $failures = array_values(array_filter($responses, static fn (array $response): bool => ! $response['ok']));
        self::assertCount(1, $successes);
        self::assertCount(1, $failures);
        self::assertSame('target_conflict', $failures[0]['reason'] ?? null);

        $winnerId = (string) ($successes[0]['site_id'] ?? '');
        self::assertContains($winnerId, ['alpha', 'beta']);
        $winner = $winnerId === 'alpha' ? $alpha : $beta;
        $loser = $winnerId === 'alpha' ? $beta : $alpha;
        $loserBase = $winnerId === 'alpha' ? 'https://beta.example.test' : 'https://alpha.example.test';

        $winner->refresh();
        $loser->refresh();
        self::assertSame($target, $winner->base_url);
        self::assertSame(SiteConnectionState::Disconnected, $winner->connection_state);
        self::assertFalse($winner->credential()->exists());
        self::assertSame($loserBase, $loser->base_url);
        self::assertSame(SiteConnectionState::Connected, $loser->connection_state);
        self::assertTrue($loser->credential()->exists());
        self::assertSame(1, Site::query()->where('base_url_hash', hash('sha256', $target))->count());
        self::assertEqualsCanonicalizing(
            [$winnerId.'-refresh', $winnerId.'-access'],
            $logs['revoke'],
            'The losing target update must detect ownership before revoking its existing remote credential.',
        );
    }

    public function test_target_update_and_create_share_the_same_target_ownership_boundary(): void
    {
        $alpha = $this->connectedSiteWithCredential('alpha', 'https://alpha.example.test');
        $target = 'https://shared.example.test';

        [$responses, $logs] = $this->runConcurrentActions($alpha, [
            [
                'action' => 'update',
                'site_record_id' => (string) $alpha->getKey(),
                'display_name' => 'Alpha',
                'target_base_url' => $target,
                'revoke_delay_us' => 750_000,
            ],
            [
                'action' => 'create',
                'new_site_id' => 'gamma',
                'display_name' => 'Gamma',
                'target_base_url' => $target,
                'discovery_delay_us' => 250_000,
            ],
        ], false);

        $update = $this->responseFor($responses, 'update');
        $create = $this->responseFor($responses, 'create');
        self::assertNotSame($update['ok'], $create['ok']);
        self::assertSame('target_conflict', ($update['ok'] ? $create : $update)['reason'] ?? null);
        self::assertSame(1, Site::query()->where('base_url_hash', hash('sha256', $target))->count());

        $alpha->refresh();
        if ($update['ok']) {
            self::assertSame($target, $alpha->base_url);
            self::assertSame(SiteConnectionState::Disconnected, $alpha->connection_state);
            self::assertFalse($alpha->credential()->exists());
            self::assertNull(Site::query()->where('site_id', 'gamma')->first());
            self::assertEqualsCanonicalizing(['alpha-refresh', 'alpha-access'], $logs['revoke']);

            return;
        }

        self::assertSame('https://alpha.example.test', $alpha->base_url);
        self::assertSame(SiteConnectionState::Connected, $alpha->connection_state);
        self::assertTrue($alpha->credential()->exists());
        self::assertNotNull(Site::query()->where('site_id', 'gamma')->where('base_url', $target)->first());
        self::assertSame([], $logs['revoke']);
    }

    public function test_concurrent_begin_and_callback_have_one_serial_authoritative_outcome(): void
    {
        $site = $this->disconnectedSite();
        $oldState = $this->createPendingFlow($site);

        [$responses] = $this->runConcurrentActions($site, [
            ['action' => 'begin'],
            ['action' => 'callback', 'state' => $oldState],
        ]);

        $begin = $this->responseFor($responses, 'begin');
        $callback = $this->responseFor($responses, 'callback');
        $site->refresh();

        self::assertFalse($begin['ok'] && $callback['ok'], 'Begin and callback must not both commit competing lifecycle generations.');

        if ($begin['ok']) {
            self::assertFalse($callback['ok']);
            self::assertSame('invalid_state', $callback['reason'] ?? null);
            self::assertSame(SiteConnectionState::Pending, $site->connection_state);
            self::assertFalse($site->credential()->exists());
            self::assertSame(1, $site->oauthFlows()->count());
            self::assertIsString($begin['state'] ?? null);
            self::assertSame(
                hash('sha256', (string) $begin['state']),
                $site->oauthFlows()->firstOrFail()->state_hash,
            );

            return;
        }

        self::assertTrue($callback['ok']);
        self::assertSame('already_connected', $begin['reason'] ?? null);
        self::assertSame(SiteConnectionState::Connected, $site->connection_state);
        self::assertTrue($site->credential()->exists());
        self::assertSame(0, $site->oauthFlows()->count());
    }

    private function connectedSiteWithCredential(string $siteId, string $base): Site
    {
        $site = Site::query()->create([
            'site_id' => $siteId,
            'display_name' => ucfirst($siteId),
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => SiteConnectionState::Connected,
            'last_tested_at' => now(),
            'connected_at' => now(),
        ]);

        $expiresAt = new DateTimeImmutable('@'.(time() + 3600));
        $payload = app(SiteCredentialVault::class)->seal(
            $site,
            self::CLIENT_ID,
            $site->mcp_resource_url,
            $siteId.'-access',
            $siteId.'-refresh',
            $expiresAt,
            ['mcp:use', 'offline_access'],
        );
        SiteCredential::query()->create([
            'site_record_id' => $site->getKey(),
            'client_id' => self::CLIENT_ID,
            'resource_url' => $site->mcp_resource_url,
            'binding_hash' => SiteCredentialVault::bindingHash($site, self::CLIENT_ID, $site->mcp_resource_url),
            'encrypted_payload' => $payload,
            'access_expires_at' => $expiresAt,
        ]);

        return $site->refresh();
    }

    private function connectedSiteWithExpiredCredential(): Site
    {
        $site = $this->disconnectedSite();
        $site->forceFill([
            'connection_state' => SiteConnectionState::Connected,
            'connected_at' => now(),
        ])->save();

        $expiresAt = new DateTimeImmutable('@'.(time() - 60));
        $payload = app(SiteCredentialVault::class)->seal(
            $site,
            self::CLIENT_ID,
            $site->mcp_resource_url,
            'initial-access',
            'initial-refresh',
            $expiresAt,
            ['mcp:use', 'offline_access'],
        );
        SiteCredential::query()->create([
            'site_record_id' => $site->getKey(),
            'client_id' => self::CLIENT_ID,
            'resource_url' => $site->mcp_resource_url,
            'binding_hash' => SiteCredentialVault::bindingHash($site, self::CLIENT_ID, $site->mcp_resource_url),
            'encrypted_payload' => $payload,
            'access_expires_at' => $expiresAt,
        ]);

        return $site->refresh();
    }

    private function disconnectedSite(): Site
    {
        $base = 'https://alpha.example.test';

        return Site::query()->create([
            'site_id' => 'alpha',
            'display_name' => 'Alpha',
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => SiteConnectionState::Disconnected,
            'last_tested_at' => now(),
        ]);
    }

    private function createPendingFlow(Site $site): string
    {
        $state = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $stateHash = hash('sha256', $state);
        $expiresAt = now()->addMinutes(10);
        $flow = new SiteOAuthFlow([
            'site_record_id' => (string) $site->getKey(),
            'state_hash' => $stateHash,
            'expires_at' => $expiresAt,
        ]);
        $flow->encrypted_context = app(SiteOAuthFlowVault::class)->seal(
            $site,
            $stateHash,
            self::CLIENT_ID,
            'https://gateway.example.test/oauth/sites/callback',
            $site->mcp_resource_url,
            $site->oauth_issuer_url,
            $site->oauth_token_url,
            $site->oauth_revocation_url,
            str_repeat('v', 64),
            $expiresAt->getTimestamp(),
        );
        $flow->save();
        $site->forceFill(['connection_state' => SiteConnectionState::Pending])->save();

        return $state;
    }

    /**
     * @param  list<array<string, mixed>>  $actions
     * @return array{0:list<array<string, mixed>>,1:array{refresh:list<string>,issue:list<string>,revoke:list<string>}}
     */
    private function runConcurrentActions(Site $site, array $actions, bool $blockSiteRow = true): array
    {
        $directory = storage_path('framework/testing/site-lifecycle-concurrency-'.Str::uuid());
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create site lifecycle concurrency fixture directory.');
        }

        $barrier = $directory.'/go';
        $logs = [
            'refresh' => $directory.'/refresh.log',
            'issue' => $directory.'/issued.log',
            'revoke' => $directory.'/revoked.log',
        ];
        $payloadPaths = [];
        $readyPaths = [];
        $processes = [];
        $blocker = $blockSiteRow ? $this->lockSiteRow((string) $site->getKey()) : null;

        try {
            foreach ($actions as $index => $action) {
                $payloadPath = $directory.'/payload-'.$index.'.json';
                $readyPath = $directory.'/ready-'.$index;
                $payloadPaths[] = $payloadPath;
                $readyPaths[] = $readyPath;
                $payload = [
                    'site_record_id' => (string) $site->getKey(),
                    ...$action,
                    'refresh_log' => $logs['refresh'],
                    'issue_log' => $logs['issue'],
                    'revoke_log' => $logs['revoke'],
                ];
                $this->writePrivateFixture($payloadPath, json_encode($payload, JSON_THROW_ON_ERROR));

                $pipes = [];
                $process = proc_open([
                    PHP_BINARY,
                    base_path('tests/Support/site_lifecycle_concurrent_action.php'),
                    $payloadPath,
                    $barrier,
                    $readyPath,
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());
                if (! is_resource($process)) {
                    throw new RuntimeException('Could not start site lifecycle concurrency worker.');
                }
                $processes[] = ['process' => $process, 'pipes' => $pipes];
            }

            $deadline = microtime(true) + 10;
            while (count(array_filter($readyPaths, 'is_file')) !== count($readyPaths)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Site lifecycle concurrency workers did not become ready.');
                }
                usleep(1000);
            }

            if (! touch($barrier)) {
                throw new RuntimeException('Could not release site lifecycle concurrency barrier.');
            }

            if ($blocker instanceof PDO) {
                usleep(250_000);
                $blocker->commit();
            }

            $responses = [];
            foreach ($processes as $worker) {
                $stdout = stream_get_contents($worker['pipes'][1]);
                $stderr = stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                $exitCode = proc_close($worker['process']);
                self::assertSame(0, $exitCode, trim((string) $stderr));
                $response = json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR);
                self::assertIsArray($response);
                $responses[] = $response;
            }

            return [$responses, [
                'refresh' => $this->readLines($logs['refresh']),
                'issue' => $this->readLines($logs['issue']),
                'revoke' => $this->readLines($logs['revoke']),
            ]];
        } finally {
            if ($blocker instanceof PDO && $blocker->inTransaction()) {
                $blocker->rollBack();
            }
            foreach ($processes as $worker) {
                if (is_resource($worker['process'])) {
                    proc_terminate($worker['process']);
                }
            }
            foreach ([$barrier, ...$payloadPaths, ...$readyPaths, ...array_values($logs)] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
            if (is_dir($directory)) {
                rmdir($directory);
            }
        }
    }

    private function lockSiteRow(string $siteRecordId): PDO
    {
        $connection = config('database.connections.mysql');
        if (! is_array($connection)) {
            throw new RuntimeException('MySQL test connection is unavailable.');
        }

        $pdo = new PDO(
            sprintf(
                'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
                (string) ($connection['host'] ?? '127.0.0.1'),
                (string) ($connection['port'] ?? '3306'),
                (string) ($connection['database'] ?? ''),
            ),
            (string) ($connection['username'] ?? ''),
            (string) ($connection['password'] ?? ''),
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ],
        );
        $pdo->beginTransaction();
        $statement = $pdo->prepare('SELECT id FROM sites WHERE id = ? FOR UPDATE');
        $statement->execute([$siteRecordId]);
        if ($statement->fetchColumn() === false) {
            $pdo->rollBack();
            throw new RuntimeException('Site lifecycle concurrency lock target no longer exists.');
        }

        return $pdo;
    }

    /**
     * @param  list<array<string, mixed>>  $responses
     * @return array<string, mixed>
     */
    private function responseFor(array $responses, string $action): array
    {
        foreach ($responses as $response) {
            if (($response['action'] ?? null) === $action) {
                return $response;
            }
        }

        self::fail('Missing concurrency response for action '.$action.'.');
    }

    /** @param array{refresh:list<string>,issue:list<string>,revoke:list<string>} $logs */
    private function assertEveryIssuedTokenWasRevoked(array $logs): void
    {
        if ($logs['issue'] === []) {
            return;
        }

        foreach ($logs['issue'] as $token) {
            self::assertContains($token, $logs['revoke'], 'A rotated remote token was issued but not revoked.');
        }
    }

    /** @return list<string> */
    private function readLines(string $path): array
    {
        if (! is_file($path)) {
            return [];
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        return $lines === false ? [] : $lines;
    }

    private function writePrivateFixture(string $path, string $contents): void
    {
        if (file_put_contents($path, $contents, LOCK_EX) === false || ! chmod($path, 0600)) {
            throw new RuntimeException('Could not write site lifecycle concurrency fixture.');
        }
    }
}
