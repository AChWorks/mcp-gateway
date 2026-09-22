<?php

declare(strict_types=1);

use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteConnectionService;
use App\Application\Sites\SiteRegistry;
use App\Domain\Sites\Site;
use App\Infrastructure\Http\DnsResolver;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

require dirname(__DIR__, 2).'/vendor/autoload.php';

if ($argc !== 4) {
    fwrite(STDERR, "usage: site_lifecycle_concurrent_action.php <payload> <barrier> <ready>\n");
    exit(2);
}

[, $payloadPath, $barrierPath, $readyPath] = $argv;
$app = require dirname(__DIR__, 2).'/bootstrap/app.php';
$kernel = $app->make(Kernel::class);
$kernel->bootstrap();

try {
    $payload = json_decode((string) file_get_contents($payloadPath), true, flags: JSON_THROW_ON_ERROR);
    if (! is_array($payload)) {
        throw new RuntimeException('Concurrency action payload is invalid.');
    }

    config()->set('bridge.client.id', 'https://gateway.example.test/oauth/client.json');
    config()->set('bridge.client.name', 'MCP Gateway Concurrency Test');
    config()->set('bridge.client.redirect_uri', 'https://gateway.example.test/oauth/sites/callback');
    config()->set('bridge.client.jwks_uri', 'https://gateway.example.test/oauth/jwks.json');

    $app->instance(DnsResolver::class, new class implements DnsResolver
    {
        public function resolve(string $host): array
        {
            return str_ends_with($host, '.example.test') ? ['1.1.1.1'] : [];
        }
    });

    Http::preventStrayRequests();
    Http::fake(function (Request $request) use ($payload) {
        $url = $request->url();
        $host = (string) parse_url($url, PHP_URL_HOST);
        $base = 'https://'.$host;
        $path = (string) parse_url($url, PHP_URL_PATH);

        if ($path === '/.well-known/oauth-protected-resource') {
            return Http::response([
                'resource' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => ['mcp:use', 'offline_access'],
                'bearer_methods_supported' => ['header'],
                'resource_name' => 'WP AI Bridge',
            ], 200);
        }

        if ($path === '/.well-known/oauth-authorization-server') {
            $delay = max(0, (int) ($payload['discovery_delay_us'] ?? 0));
            if ($delay > 0) {
                usleep($delay);
            }

            return Http::response([
                'issuer' => $base,
                'authorization_endpoint' => $base.'/wp-ai-bridge/oauth/authorize',
                'token_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
                'revocation_endpoint' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
                'client_id_metadata_document_supported' => true,
                'authorization_response_iss_parameter_supported' => true,
                'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
                'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'response_types_supported' => ['code'],
                'code_challenge_methods_supported' => ['S256'],
                'scopes_supported' => ['mcp:use', 'offline_access'],
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/token') {
            $data = $request->data();
            $grant = (string) ($data['grant_type'] ?? '');
            if ($grant === 'refresh_token') {
                $refreshLog = is_string($payload['refresh_log'] ?? null) ? $payload['refresh_log'] : null;
                $attempt = 1;
                if ($refreshLog !== null) {
                    $handle = fopen($refreshLog, 'c+');
                    if ($handle === false || ! flock($handle, LOCK_EX)) {
                        throw new RuntimeException('Could not lock refresh concurrency log.');
                    }
                    $contents = stream_get_contents($handle);
                    $attempt = $contents === '' ? 1 : count(array_filter(explode("\n", trim((string) $contents)))) + 1;
                    fseek($handle, 0, SEEK_END);
                    fwrite($handle, "attempt-{$attempt}\n");
                    fflush($handle);
                    flock($handle, LOCK_UN);
                    fclose($handle);
                }

                if ($attempt > 1) {
                    return Http::response(['error' => 'invalid_grant'], 400);
                }

                $issueLog = is_string($payload['issue_log'] ?? null) ? $payload['issue_log'] : null;
                if ($issueLog !== null) {
                    file_put_contents($issueLog, "rotated-refresh\nrotated-access\n", FILE_APPEND | LOCK_EX);
                }
                $delay = max(0, (int) ($payload['refresh_delay_us'] ?? 0));
                if ($delay > 0) {
                    usleep($delay);
                }

                return Http::response([
                    'token_type' => 'Bearer',
                    'expires_in' => 3600,
                    'access_token' => 'rotated-access',
                    'refresh_token' => 'rotated-refresh',
                    'scope' => 'mcp:use offline_access',
                ], 200);
            }

            return Http::response([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'access_token' => 'callback-access',
                'refresh_token' => 'callback-refresh',
                'scope' => 'mcp:use offline_access',
            ], 200);
        }

        if ($path === '/wp-json/wp-ai-bridge/v1/oauth/revoke') {
            $token = (string) ($request->data()['token'] ?? '');
            $revokeLog = is_string($payload['revoke_log'] ?? null) ? $payload['revoke_log'] : null;
            $revokeNumber = 0;
            if ($revokeLog !== null) {
                $handle = fopen($revokeLog, 'c+');
                if ($handle === false || ! flock($handle, LOCK_EX)) {
                    throw new RuntimeException('Could not lock revocation concurrency log.');
                }
                $contents = stream_get_contents($handle);
                $revokeNumber = $contents === '' ? 1 : count(array_filter(explode("\n", trim((string) $contents)))) + 1;
                fseek($handle, 0, SEEK_END);
                fwrite($handle, $token."\n");
                fflush($handle);
                flock($handle, LOCK_UN);
                fclose($handle);
            }

            if (($payload['signal_revoke_started'] ?? false) === true) {
                $signal = is_string($payload['revoke_started_path'] ?? null) ? $payload['revoke_started_path'] : null;
                if ($signal !== null && ! is_file($signal) && ! touch($signal)) {
                    throw new RuntimeException('Could not signal remote revocation start.');
                }
            }

            $killOnRevoke = max(0, (int) ($payload['kill_database_on_revoke_number'] ?? 0));
            if ($killOnRevoke > 0 && $revokeNumber === $killOnRevoke) {
                $row = DB::selectOne('SELECT CONNECTION_ID() AS connection_id');
                $connectionId = is_object($row) ? (int) ($row->connection_id ?? 0) : 0;
                if ($connectionId <= 0) {
                    throw new RuntimeException('Could not resolve the active database connection id.');
                }
                killDatabaseConnection($connectionId);
                $killLog = is_string($payload['kill_log'] ?? null) ? $payload['kill_log'] : null;
                if ($killLog !== null) {
                    file_put_contents($killLog, $connectionId."\n", FILE_APPEND | LOCK_EX);
                }
            }

            $delay = max(0, (int) ($payload['revoke_delay_us'] ?? 0));
            if ($delay > 0) {
                usleep($delay);
            }

            return Http::response('', 200);
        }

        return Http::response(['error' => 'not_found'], 404);
    });

    if (! touch($readyPath)) {
        throw new RuntimeException('Concurrency worker could not signal readiness.');
    }

    $deadline = microtime(true) + 10;
    while (! is_file($barrierPath)) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Concurrency worker timed out waiting for the start barrier.');
        }
        usleep(1000);
    }

    if (($payload['wait_for_revoke_started'] ?? false) === true) {
        $signal = is_string($payload['revoke_started_path'] ?? null) ? $payload['revoke_started_path'] : null;
        if ($signal === null) {
            throw new RuntimeException('Missing revocation-start signal path.');
        }
        $signalDeadline = microtime(true) + 10;
        while (! is_file($signal)) {
            if (microtime(true) >= $signalDeadline) {
                throw new RuntimeException('Timed out waiting for remote revocation to start.');
            }
            usleep(1000);
        }
    }

    $action = (string) ($payload['action'] ?? '');
    $site = null;
    if ($action !== 'create') {
        $siteId = (string) ($payload['site_record_id'] ?? '');
        $site = Site::query()->find($siteId);
        if (! $site instanceof Site) {
            throw new SiteConnectionException('site_not_found', 'The site no longer exists.');
        }
    }

    $result = [
        'ok' => true,
        'action' => $action,
        'site_id' => $site?->site_id,
    ];

    try {
        if ($action === 'access') {
            $result['access_token'] = app(SiteConnectionService::class)->accessToken($site);
        } elseif ($action === 'disconnect') {
            app(SiteConnectionService::class)->disconnect($site);
        } elseif ($action === 'remove') {
            app(SiteRegistry::class)->remove($site);
        } elseif ($action === 'begin') {
            $url = app(SiteConnectionService::class)->begin($site);
            parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
            $result['state'] = is_string($query['state'] ?? null) ? $query['state'] : null;
        } elseif ($action === 'callback') {
            app(SiteConnectionService::class)->completeCallback(
                (string) ($payload['state'] ?? ''),
                'callback-code',
                $site->base_url,
                null,
            );
        } elseif ($action === 'update') {
            $updated = app(SiteRegistry::class)->update(
                $site,
                (string) ($payload['display_name'] ?? $site->display_name),
                (string) ($payload['target_base_url'] ?? ''),
            );
            $result['base_url'] = $updated->base_url;
        } elseif ($action === 'create') {
            $created = app(SiteRegistry::class)->create(
                (string) ($payload['new_site_id'] ?? ''),
                (string) ($payload['display_name'] ?? ''),
                (string) ($payload['target_base_url'] ?? ''),
            );
            $result['site_id'] = $created->site_id;
            $result['base_url'] = $created->base_url;
        } else {
            throw new RuntimeException('Unsupported site lifecycle concurrency action.');
        }
    } catch (SiteConnectionException $exception) {
        $result = [
            'ok' => false,
            'action' => $action,
            'site_id' => $site?->site_id,
            'reason' => $exception->reason,
        ];
    } catch (InvalidArgumentException $exception) {
        $result = [
            'ok' => false,
            'action' => $action,
            'site_id' => $site?->site_id,
            'reason' => 'target_conflict',
        ];
    } catch (Throwable $exception) {
        if (($payload['capture_throwable'] ?? false) !== true) {
            throw $exception;
        }
        $result = [
            'ok' => false,
            'action' => $action,
            'site_id' => $site?->site_id,
            'reason' => 'unexpected_exception',
            'exception_class' => $exception::class,
        ];
    }

    echo json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
} catch (SiteConnectionException $exception) {
    echo json_encode([
        'ok' => false,
        'action' => is_array($payload ?? null) ? (string) ($payload['action'] ?? '') : '',
        'reason' => $exception->reason,
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n");
    exit(1);
}

function killDatabaseConnection(int $connectionId): void
{
    $connection = DB::connection()->getConfig();
    if (! is_array($connection)) {
        throw new RuntimeException('Database test connection is unavailable.');
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
    $pdo->exec('KILL CONNECTION '.(int) $connectionId);
}
