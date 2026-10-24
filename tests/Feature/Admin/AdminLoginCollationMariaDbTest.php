<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
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

    public function test_valid_login_clears_canonical_id_counter_and_unknown_alias_has_generic_errors(): void
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

    public function test_parallel_failed_aliases_cannot_overrun_canonical_account_budget(): void
    {
        $user = $this->owner('owner@cafe.example.test');
        $key = 'admin-login:failed-identity:user:'.$user->id;
        RateLimiter::clear($key);

        for ($i = 0; $i < 8; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.'.($i + 1)])
                ->post('/admin/login', [
                    'email' => $i % 2 ? 'owner@café.example.test' : $user->email,
                    'password' => 'wrong-password',
                ])->assertSessionHasErrors('email');
        }

        $folder = storage_path('framework/testing/admin-login-race-'.Str::uuid());
        if (! mkdir($folder, 0700, true) && ! is_dir($folder)) {
            throw new RuntimeException('Could not make isolated login concurrency fixture.');
        }
        $barrier = $folder.'/go';
        $workers = [];

        try {
            for ($i = 0; $i < 4; $i++) {
                $ready = $folder.'/ready-'.$i;
                $pipes = [];
                $worker = proc_open([
                    PHP_BINARY, base_path('tests/Support/admin_concurrent_login_request.php'),
                    $barrier, $ready, $i % 2 ? 'owner@café.example.test' : $user->email,
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
            self::assertSame(10, RateLimiter::attempts($key));
        } finally {
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
    }

    private function owner(string $email): User
    {
        return User::query()->create([
            'name' => 'Fixture Owner', 'email' => $email,
            'password' => 'CorrectHorse!234', 'role' => GatewayRole::Owner->value,
        ]);
    }
}
