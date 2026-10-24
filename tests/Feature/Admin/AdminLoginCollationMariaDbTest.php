<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Models\User;
use App\Support\AdminLoginIdentity;
use Illuminate\Cache\RateLimiter as CacheRateLimiter;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\TestCase;

#[Group('database-concurrency')]
final class AdminLoginCollationMariaDbTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (! in_array(DB::getDriverName(), ['mariadb', 'mysql'], true)) {
            $this->markTestSkipped('Real MariaDB/MySQL collation and shared locks are required.');
        }

        Artisan::call('migrate:fresh', ['--force' => true]);
        config()->set('cache.default', 'file');
        config()->set('cache.limiter', 'file');
    }

    public function test_database_equivalent_unicode_aliases_share_a_user_budget_across_ips(): void
    {
        $user = $this->owner('owner@cafe.example.test');
        $aliases = ['owner@cafe.example.test', 'owner@café.example.test', 'OWNER@CAFÉ.EXAMPLE.TEST'];
        foreach ($aliases as $email) {
            self::assertTrue(Validator::make(['email' => $email], [
                'email' => ['required', 'string', 'email:rfc', 'max:254'],
            ])->passes(), $email);
            self::assertSame($user->id, (int) DB::table('users')->where('email', $email)->value('id'));
        }

        for ($i = 0; $i < 10; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.($i + 1)])
                ->post('/admin/login', [
                    'email' => $aliases[$i % count($aliases)],
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email');
        }

        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.11'])
            ->post('/admin/login', [
                'email' => 'OWNER@CAFÉ.EXAMPLE.TEST',
                'password' => 'CorrectHorse!234',
            ])->assertTooManyRequests()->assertHeader('Retry-After');

        // An unrelated account has its own limiter identity and can log in.
        $other = $this->owner('other@cafe.example.test');
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.12'])
            ->post('/admin/login', ['email' => $other->email, 'password' => 'CorrectHorse!234'])
            ->assertRedirect('/admin');
    }

    public function test_existing_and_missing_unicode_equivalent_accounts_have_identical_quota_responses(): void
    {
        $this->owner('owner@cafe.example.test');

        $known = ['owner@cafe.example.test', 'owner@café.example.test'];
        $missing = ['absent@cafe.example.test', 'absent@café.example.test'];
        self::assertSame(
            DB::scalar('SELECT COLLATION(email) FROM users LIMIT 1'),
            DB::scalar('SELECT COLLATION(?)', [$known[0]]),
            'The login comparison-weight connection must match the real users.email column collation.',
        );
        $identity = app(AdminLoginIdentity::class);
        self::assertSame($identity->failureKey($known[0]), $identity->failureKey($known[1]));
        self::assertSame($identity->failureKey($missing[0]), $identity->failureKey($missing[1]));
        self::assertNotSame($identity->failureKey($known[0]), $identity->failureKey($missing[0]));

        foreach ($missing as $email) {
            self::assertNull(DB::table('users')->where('email', $email)->value('id'));
        }

        $observations = [];
        foreach (['known' => $known, 'missing' => $missing] as $scenario => $aliases) {
            $observations[$scenario] = [];
            for ($i = 0; $i <= 10; $i++) {
                // Distinct IPs make the cross-IP identity budget decisive.
                $response = $this->withServerVariables(['REMOTE_ADDR' => '192.0.'.($scenario === 'known' ? '2' : '3').'.'.($i + 1)])
                    ->post('/admin/login', [
                        'email' => $aliases[$i % 2],
                        'password' => 'wrong-password',
                    ]);
                $observations[$scenario][] = [
                    'status' => $response->getStatusCode(),
                    'retry' => $response->headers->has('Retry-After'),
                ];
                if ($i === 10) {
                    $response->assertTooManyRequests()->assertHeader('Retry-After');
                } else {
                    $response->assertSessionHasErrors('email', __('The provided credentials are invalid.'));
                }
            }
        }

        self::assertSame($observations['known'], $observations['missing']);
        self::assertSame(array_merge(
            array_fill(0, 10, ['status' => 302, 'retry' => false]),
            [['status' => 429, 'retry' => true]],
        ), $observations['known']);
    }

    public function test_valid_login_clears_collation_equivalent_counter_and_unknown_alias_has_generic_errors(): void
    {
        $user = $this->owner('owner@cafe.example.test');

        for ($i = 0; $i < 9; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.($i + 1)])
                ->post('/admin/login', [
                    'email' => $i % 2 ? 'owner@café.example.test' : $user->email,
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email', __('The provided credentials are invalid.'));
        }

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.10'])
            ->post('/admin/login', [
                'email' => 'owner@café.example.test',
                'password' => 'CorrectHorse!234',
            ])->assertRedirect('/admin');
        $this->post('/admin/logout')->assertRedirect('/admin/login');

        for ($i = 0; $i < 9; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.($i + 11)])
                ->post('/admin/login', [
                    'email' => 'OWNER@CAFÉ.EXAMPLE.TEST',
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email');
        }
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->post('/admin/login', [
                'email' => $user->email, 'password' => 'CorrectHorse!234',
            ])->assertRedirect('/admin');

        $this->post('/admin/logout')->assertRedirect('/admin/login');
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.21'])
            ->post('/admin/login', [
                'email' => 'unknown@café.example.test', 'password' => 'wrong-password',
            ])->assertSessionHasErrors('email', __('The provided credentials are invalid.'));
    }

    public function test_parallel_existing_and_missing_aliases_have_the_same_serialized_budget(): void
    {
        $this->owner('owner@cafe.example.test');

        $known = $this->runParallelAliasBudget('owner@cafe.example.test', 'owner@café.example.test');
        $missing = $this->runParallelAliasBudget('absent@cafe.example.test', 'absent@café.example.test');

        self::assertSame($known, $missing);
    }

    /**
     * @return array<int, int>
     */
    private function runParallelAliasBudget(string $primaryEmail, string $aliasEmail): array
    {
        $key = app(AdminLoginIdentity::class)->failureKey($primaryEmail);
        self::assertSame($key, app(AdminLoginIdentity::class)->failureKey($aliasEmail));
        // File store is shared by external PHP workers. The parent PHPUnit
        // application was booted with an array limiter, so inspect the
        // actual shared store with an explicit RateLimiter instance.
        $fileLimiter = new CacheRateLimiter(Cache::store('file'));
        $fileLimiter->clear($key);

        $folder = storage_path('framework/testing/admin-login-race-'.Str::uuid());
        if (! mkdir($folder, 0700, true) && ! is_dir($folder)) {
            throw new RuntimeException('Could not make isolated login concurrency fixture.');
        }
        $barrier = $folder.'/go';
        $workers = [];

        try {
            $warmBarrier = $folder.'/warm-go';
            $warmReady = $folder.'/warm-ready';
            if (! touch($warmBarrier)) {
                throw new RuntimeException('Could not start warm-up fixture.');
            }

            $warmPipes = [];
            $warm = proc_open([
                PHP_BINARY, base_path('tests/Support/admin_concurrent_login_request.php'),
                $warmBarrier, $warmReady, $primaryEmail, '203.0.113.1', '8',
            ], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $warmPipes, base_path());
            if (! is_resource($warm)) {
                throw new RuntimeException('Could not start warm-up worker.');
            }

            $warmStdout = stream_get_contents($warmPipes[1]);
            $warmStderr = stream_get_contents($warmPipes[2]);
            fclose($warmPipes[1]);
            fclose($warmPipes[2]);
            self::assertSame(0, proc_close($warm), trim((string) $warmStderr));
            self::assertSame(array_fill(0, 8, 302),
                json_decode((string) $warmStdout, true, flags: JSON_THROW_ON_ERROR)['statuses']);
            self::assertSame(8, $fileLimiter->attempts($key));

            for ($i = 0; $i < 4; $i++) {
                $ready = $folder.'/ready-'.$i;
                $pipes = [];
                $worker = proc_open([
                    PHP_BINARY, base_path('tests/Support/admin_concurrent_login_request.php'),
                    $barrier, $ready, $i % 2 ? $aliasEmail : $primaryEmail,
                    '203.0.113.'.($i + 31),
                ], [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ], $pipes, base_path());

                if (! is_resource($worker)) {
                    throw new RuntimeException('Could not start login concurrency worker.');
                }
                $workers[] = ['worker' => $worker, 'pipes' => $pipes, 'ready' => $ready];
            }

            $deadline = microtime(true) + 15;
            foreach ($workers as $worker) {
                while (! is_file($worker['ready'])) {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('Login concurrency worker readiness timed out.');
                    }
                    usleep(1000);
                }
            }
            if (! touch($barrier)) {
                throw new RuntimeException('Could not release login concurrency barrier.');
            }

            $codes = [];
            foreach ($workers as $worker) {
                $stdout = stream_get_contents($worker['pipes'][1]);
                $stderr = stream_get_contents($worker['pipes'][2]);
                fclose($worker['pipes'][1]);
                fclose($worker['pipes'][2]);
                $exit = proc_close($worker['worker']);
                self::assertSame(0, $exit, trim((string) $stderr));
                $codes[] = json_decode((string) $stdout, true, flags: JSON_THROW_ON_ERROR)['status'];
            }
            sort($codes);
            self::assertSame([302, 302, 429, 429], $codes);
            self::assertSame(10, $fileLimiter->attempts($key));
        } finally {
            $fileLimiter->clear($key);
            foreach ($workers as $worker) {
                if (is_resource($worker['worker'])) {
                    proc_terminate($worker['worker']);
                    proc_close($worker['worker']);
                }
            }
            foreach (glob($folder.'/*') ?: [] as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            rmdir($folder);
        }
        self::assertSame(0, $fileLimiter->attempts($key));

        return $codes;
    }

    private function owner(string $email): User
    {
        return User::query()->create([
            'name' => 'Fixture Owner', 'email' => $email,
            'password' => 'CorrectHorse!234', 'role' => GatewayRole::Owner->value,
        ]);
    }
}
