<?php

namespace Tests\Feature\OAuth;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use App\Models\User;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('mysql-concurrency')]
final class OAuthTokenConcurrencyTest extends TestCase
{
    private const CLIENT_ID = 'https://chatgpt.com/oauth/client.json';

    private const REDIRECT_URI = 'https://chatgpt.com/connector_platform_oauth_redirect';

    private const CLIENT_KID = 'test-chatgpt-key';

    private string $clientPrivateKey;

    /** @var array<string, mixed> */
    private array $clientJwk;

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::getDriverName() !== 'mysql') {
            $this->markTestSkipped('MySQL is required for row-lock concurrency validation.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
        Artisan::call('gateway:oauth-keygen', ['--force' => true]);
        [$this->clientPrivateKey, $this->clientJwk] = $this->newClientKeypair();
        $this->bindClientMetadataFixture();
    }

    protected function tearDown(): void
    {
        if (DB::getDriverName() === 'mysql') {
            DB::unprepared('DROP TRIGGER IF EXISTS oauth_access_token_insert_delay');
            DB::unprepared('DROP TRIGGER IF EXISTS oauth_access_token_update_delay');
        }

        parent::tearDown();
    }

    public function test_authorization_code_can_only_be_redeemed_once_under_concurrency(): void
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user, 'mcp offline_access');
        $this->installAccessTokenInsertDelay();

        $base = [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        ];

        $responses = $this->runConcurrentTokenRequests(
            [...$base, 'client_assertion' => $this->clientAssertion()],
            [...$base, 'client_assertion' => $this->clientAssertion()],
        );

        self::assertSame([200, 400], $this->sortedStatuses($responses));
        self::assertSame(1, DB::table('oauth_access_tokens')->count());
        self::assertSame(1, DB::table('oauth_refresh_tokens')->count());
        self::assertSame(1, DB::table('oauth_auth_codes')->whereNotNull('revoked_at')->count());
    }

    public function test_refresh_token_rotation_has_only_one_successor_under_concurrency(): void
    {
        $user = $this->operator();
        [$code, $verifier] = $this->approvedAuthorizationCode($user, 'mcp offline_access');
        $initial = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion(),
        ]);
        $initial->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
        $refreshToken = (string) $initial->json('refresh_token');

        $this->installAccessTokenUpdateDelay();
        $base = [
            'grant_type' => 'refresh_token',
            'client_id' => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'resource' => config('oauth.resource'),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        ];

        $responses = $this->runConcurrentTokenRequests(
            [...$base, 'client_assertion' => $this->clientAssertion()],
            [...$base, 'client_assertion' => $this->clientAssertion()],
        );

        self::assertSame([200, 400], $this->sortedStatuses($responses));
        self::assertSame(2, DB::table('oauth_access_tokens')->count());
        self::assertSame(2, DB::table('oauth_refresh_tokens')->count());
        self::assertSame(1, DB::table('oauth_refresh_tokens')->whereNotNull('revoked_at')->count());
        self::assertSame(1, DB::table('oauth_refresh_tokens')->whereNull('revoked_at')->count());
    }

    private function installAccessTokenInsertDelay(): void
    {
        DB::unprepared('DROP TRIGGER IF EXISTS oauth_access_token_insert_delay');
        DB::unprepared(
            'CREATE TRIGGER oauth_access_token_insert_delay '
            .'BEFORE INSERT ON oauth_access_tokens FOR EACH ROW DO SLEEP(0.5)',
        );
    }

    private function installAccessTokenUpdateDelay(): void
    {
        DB::unprepared('DROP TRIGGER IF EXISTS oauth_access_token_update_delay');
        DB::unprepared(
            'CREATE TRIGGER oauth_access_token_update_delay '
            .'BEFORE UPDATE ON oauth_access_tokens FOR EACH ROW DO SLEEP(0.5)',
        );
    }

    /**
     * @param  array<string, mixed>  $firstPayload
     * @param  array<string, mixed>  $secondPayload
     * @return array<int, array{status: int, body: mixed}>
     */
    private function runConcurrentTokenRequests(array $firstPayload, array $secondPayload): array
    {
        $directory = storage_path('framework/testing/oauth-concurrency-'.Str::uuid());
        if (! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Could not create OAuth concurrency fixture directory.');
        }

        $barrier = $directory.'/go';
        $jwkPath = $directory.'/client-jwk.json';
        $payloadPaths = [$directory.'/payload-1.json', $directory.'/payload-2.json'];
        $readyPaths = [$directory.'/ready-1', $directory.'/ready-2'];
        $payloads = [$firstPayload, $secondPayload];
        $processes = [];

        try {
            $this->writePrivateFixture($jwkPath, json_encode($this->clientJwk, JSON_THROW_ON_ERROR));
            foreach ($payloads as $index => $payload) {
                $this->writePrivateFixture(
                    $payloadPaths[$index],
                    json_encode($payload, JSON_THROW_ON_ERROR),
                );

                $pipes = [];
                $process = proc_open([
                    PHP_BINARY,
                    base_path('tests/Support/oauth_concurrent_token_request.php'),
                    $payloadPaths[$index],
                    $jwkPath,
                    $barrier,
                    $readyPaths[$index],
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());

                if (! is_resource($process)) {
                    throw new RuntimeException('Could not start OAuth concurrency worker.');
                }

                $processes[] = ['process' => $process, 'pipes' => $pipes];
            }

            $deadline = microtime(true) + 10;
            while (! is_file($readyPaths[0]) || ! is_file($readyPaths[1])) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('OAuth concurrency workers did not become ready.');
                }

                usleep(1000);
            }

            if (! touch($barrier)) {
                throw new RuntimeException('Could not release OAuth concurrency start barrier.');
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
                self::assertIsInt($response['status'] ?? null);
                $responses[] = $response;
            }

            return $responses;
        } finally {
            foreach ($processes as $worker) {
                if (is_resource($worker['process'])) {
                    proc_terminate($worker['process']);
                }
            }

            foreach ([$barrier, $jwkPath, ...$payloadPaths, ...$readyPaths] as $path) {
                if (is_file($path)) {
                    unlink($path);
                }
            }
            if (is_dir($directory)) {
                rmdir($directory);
            }
        }
    }

    /** @param array<int, array{status: int, body: mixed}> $responses
     * @return list<int>
     */
    private function sortedStatuses(array $responses): array
    {
        $statuses = array_map(static fn (array $response): int => $response['status'], $responses);
        sort($statuses, SORT_NUMERIC);

        return array_values($statuses);
    }

    private function writePrivateFixture(string $path, string $contents): void
    {
        if (file_put_contents($path, $contents, LOCK_EX) === false || ! chmod($path, 0600)) {
            throw new RuntimeException('Could not write OAuth concurrency fixture.');
        }
    }

    /** @return array{0: string, 1: string} */
    private function approvedAuthorizationCode(User $user, string $scope): array
    {
        $verifier = str_repeat('v', 64);
        $parameters = [
            'response_type' => 'code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => $scope,
            'state' => 'state-'.Str::uuid(),
            'code_challenge' => $this->s256($verifier),
            'code_challenge_method' => 'S256',
            'resource' => (string) config('oauth.resource'),
        ];
        $response = $this->actingAs($user)->post('/oauth/authorize', [
            ...$parameters,
            'decision' => 'approve',
        ]);
        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        self::assertIsString($query['code'] ?? null);

        return [$query['code'], $verifier];
    }

    private function clientAssertion(): string
    {
        $now = time();

        return JWT::encode([
            'iss' => self::CLIENT_ID,
            'sub' => self::CLIENT_ID,
            'aud' => (string) config('oauth.issuer').'/oauth/token',
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => (string) Str::uuid(),
        ], $this->clientPrivateKey, 'RS256', self::CLIENT_KID);
    }

    private function s256(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function operator(): User
    {
        return User::query()->create([
            'name' => 'Gateway Operator',
            'email' => 'operator-concurrency@example.test',
            'password' => Hash::make('test-password-not-used-for-oauth'),
        ]);
    }

    private function bindClientMetadataFixture(): void
    {
        $metadata = [
            'client_id' => self::CLIENT_ID,
            'client_uri' => 'https://chatgpt.com/',
            'redirect_uris' => [self::REDIRECT_URI],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'client_name' => 'ChatGPT',
            'token_endpoint_auth_signing_alg' => 'RS256',
            'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
        ];
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($metadata, JSON_THROW_ON_ERROR)),
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => [$this->clientJwk]], JSON_THROW_ON_ERROR)),
            new Response(200, ['Content-Type' => 'application/json'], json_encode($metadata, JSON_THROW_ON_ERROR)),
            new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => [$this->clientJwk]], JSON_THROW_ON_ERROR)),
        ]);
        $this->app->instance(
            ChatGptClientMetadata::class,
            new ChatGptClientMetadata(new Client(['handler' => HandlerStack::create($mock)])),
        );
    }

    /** @return array{0: string, 1: array<string, mixed>} */
    private function newClientKeypair(): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($key);

        $privateKey = '';
        self::assertTrue(openssl_pkey_export($key, $privateKey));
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsArray($details['rsa'] ?? null);

        return [$privateKey, [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => self::CLIENT_KID,
            'n' => JWT::urlsafeB64Encode($details['rsa']['n']),
            'e' => JWT::urlsafeB64Encode($details['rsa']['e']),
        ]];
    }
}
