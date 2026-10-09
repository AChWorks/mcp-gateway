<?php

namespace Tests\Unit\Infrastructure\OAuth;

use App\Infrastructure\OAuth\ChatGptClientMetadata;
use GuzzleHttp\Client;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use Tests\TestCase;
use Throwable;

final class ChatGptMetadataSingleFlightTest extends TestCase
{
    public function test_concurrent_cold_file_cache_misses_have_only_one_metadata_fetch(): void
    {
        if (! function_exists('pcntl_fork') || ! function_exists('pcntl_waitpid')) {
            $this->markTestSkipped('pcntl is required for multi-process file-cache validation.');
        }

        $directory = sys_get_temp_dir().'/oauth-metadata-singleflight-'.Str::random(16);
        File::ensureDirectoryExists($directory);

        $previousDefault = config('cache.default');
        $previousFile = config('cache.stores.file');
        $children = [];

        try {
            config()->set('cache.stores.file.path', $directory.'/cache');
            config()->set('cache.stores.file.lock_path', $directory.'/cache');
            config()->set('cache.default', 'file');
            Cache::purge('file');
            Cache::setDefaultDriver('file');

            $fetches = $directory.'/fetches.txt';
            $start = $directory.'/start.signal';
            $metadata = json_encode([
                'client_id' => 'https://chatgpt.com/oauth/client.json',
                'client_uri' => 'https://chatgpt.com/',
                'client_name' => 'ChatGPT',
                'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'token_endpoint_auth_signing_alg' => 'RS256',
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
            ], JSON_THROW_ON_ERROR);

            for ($i = 0; $i < 5; $i++) {
                $pid = pcntl_fork();
                if ($pid === -1) {
                    throw new RuntimeException('Unable to fork file-cache test worker.');
                }

                if ($pid === 0) {
                    while (! is_file($start)) {
                        usleep(1000);
                    }

                    $handler = static function (RequestInterface $request, array $options) use ($fetches, $metadata) {
                        file_put_contents($fetches, "fetch\n", FILE_APPEND | LOCK_EX);
                        usleep(220000);

                        return Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], $metadata));
                    };

                    try {
                        $service = new ChatGptClientMetadata(new Client(['handler' => $handler]));
                        $value = $service->metadata();
                        exit(($value['client_name'] ?? null) === 'ChatGPT' ? 0 : 1);
                    } catch (Throwable $exception) {
                        file_put_contents($directory.'/worker-'.$i.'.error', $exception->getMessage());
                        exit(1);
                    }
                }

                $children[] = $pid;
            }

            touch($start);
            foreach ($children as $pid) {
                $waited = pcntl_waitpid($pid, $status);
                self::assertSame($pid, $waited);
                self::assertTrue(pcntl_wifexited($status));
                self::assertSame(0, pcntl_wexitstatus($status));
            }
            $children = [];

            self::assertTrue(is_file($fetches));
            self::assertSame(1, count(file($fetches, FILE_IGNORE_NEW_LINES)));
        } finally {
            foreach ($children as $pid) {
                if (function_exists('posix_kill')) {
                    posix_kill($pid, SIGTERM);
                }
                pcntl_waitpid($pid, $status);
            }
            config()->set('cache.default', $previousDefault);
            config()->set('cache.stores.file', $previousFile);
            Cache::purge('file');
            Cache::setDefaultDriver((string) $previousDefault);
            File::deleteDirectory($directory);
        }
    }
}
