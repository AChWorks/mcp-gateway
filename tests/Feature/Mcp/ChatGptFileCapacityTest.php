<?php

namespace Tests\Feature\Mcp;

use App\Application\Files\ChatGptFileCapacity;
use App\Application\Files\ChatGptFileIngress;
use App\Infrastructure\Http\DnsResolver;
use App\Infrastructure\Http\OutboundRequestException;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ChatGptFileCapacityTest extends TestCase
{
    use RefreshDatabase;

    private const FILE = [
        'download_url' => 'https://files.oaiusercontent.com/private/test?sig=not-published',
        'file_id' => 'test_file_param',
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->instance(DnsResolver::class, new class implements DnsResolver
        {
            public function resolve(string $host, ?int $deadlineNs = null): array
            {
                return $host === 'files.oaiusercontent.com' ? ['1.1.1.1'] : [];
            }
        });
        Http::preventStrayRequests();
    }

    public function test_held_concurrent_slots_reject_before_signed_get_and_release_after_success(): void
    {
        config()->set('bridge.file_input.capacity.max_active', 2);
        config()->set('bridge.file_input.capacity.wordpress_max_active', 2);
        $capacity = app(ChatGptFileCapacity::class);
        $one = $capacity->reserve('wordpress', 1048576, 30);
        $two = $capacity->reserve('wordpress', 1048576, 30);

        self::assertSame(2, DB::table('chatgpt_file_admission_leases')->count());
        self::assertSame(2097152, (int) DB::table('chatgpt_file_admission_leases')->sum('reserved_bytes'));
        try {
            app(ChatGptFileIngress::class)->download(self::FILE, 1048576, 30, 'wordpress');
            self::fail('No third capacity lease or signed GET is allowed.');
        } catch (OutboundRequestException $error) {
            self::assertSame('file_capacity_exceeded', $error->reason);
        }
        Http::assertNothingSent();

        $one->release();
        $one->release();
        Http::fake(static fn (Request $request) => Http::response("BINARY\x00\xff", 200, [
            'Content-Length' => '8',
        ]));
        $download = app(ChatGptFileIngress::class)->download(self::FILE, 1048576, 30, 'wordpress');
        self::assertSame(8, $download['bytes']);
        self::assertSame(hash('sha256', "BINARY\x00\xff"), $download['sha256']);
        self::assertSame(2, DB::table('chatgpt_file_admission_leases')->count());
        fclose($download['stream']);
        $download['capacity_lease']->release();
        $two->release();
        self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());
        Http::assertSentCount(1);
    }

    public function test_shared_byte_budget_accounts_for_double_ssh_spool_and_mode_slots(): void
    {
        config()->set('bridge.file_input.capacity.max_active', 4);
        config()->set('bridge.file_input.capacity.wordpress_max_active', 1);
        config()->set('bridge.file_input.capacity.ssh_max_active', 2);
        config()->set('bridge.file_input.capacity.max_reserved_bytes', 2097152);
        $capacity = app(ChatGptFileCapacity::class);

        $wp = $capacity->reserve('wordpress', 700000, 30);
        try {
            $capacity->reserve('wordpress', 100000, 30);
            self::fail('WordPress mode must enforce its own active-slot limit.');
        } catch (OutboundRequestException $error) {
            self::assertSame('file_capacity_exceeded', $error->reason);
        }
        // 700 KB WordPress + 2 x 700 KB SSH > 2 MiB total,
        // although both transfers individually meet their mode byte ceilings.
        try {
            app(ChatGptFileIngress::class)->download(self::FILE, 700000, 30, 'ssh');
            self::fail('No admission for two physical SSH spools above remaining space.');
        } catch (OutboundRequestException $error) {
            self::assertSame('file_capacity_exceeded', $error->reason);
        }
        Http::assertNothingSent();

        $ssh = $capacity->reserve('ssh', 600000, 30);
        self::assertSame(1900000, (int) DB::table('chatgpt_file_admission_leases')->sum('reserved_bytes'));
        $ssh->release();
        $wp->release();
        self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());
    }

    public function test_download_failure_and_transport_abort_release_capacity(): void
    {
        $capacity = app(ChatGptFileCapacity::class);
        Http::fake(static fn (Request $request) => Http::response('signed link expired', 403));
        try {
            app(ChatGptFileIngress::class)->download(self::FILE, 1048576, 30, 'wordpress');
            self::fail('Expired source should be rejected.');
        } catch (OutboundRequestException $error) {
            self::assertNotSame('file_capacity_exceeded', $error->reason);
        }
        self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());

        Http::fake(static function (Request $request): PromiseInterface {
            throw new ConnectionException('Simulated fixture transport timeout before response.');
        });
        try {
            app(ChatGptFileIngress::class)->download(self::FILE, 1048576, 30, 'ssh');
            self::fail('The transport timeout must never leave capacity allocated.');
        } catch (OutboundRequestException $error) {
            self::assertNotSame('file_capacity_exceeded', $error->reason);
        }
        self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());

        // Both modes can reserve again after each failed download.
        $wp = $capacity->reserve('wordpress', 1048576, 30);
        $ssh = $capacity->reserve('ssh', 1048576, 30);
        $wp->release();
        $ssh->release();
    }

    public function test_orphaned_expired_lease_is_reclaimed_atomically_and_guard_absence_fails_closed(): void
    {
        config()->set('bridge.file_input.capacity.max_active', 1);
        DB::table('chatgpt_file_admission_leases')->insert([
            'id' => (string) Str::uuid(),
            'mode' => 'wordpress',
            'reserved_bytes' => 8388608,
            'created_at' => now()->subMinutes(3),
            'expires_at' => now()->subMinutes(1),
        ]);
        $capacity = app(ChatGptFileCapacity::class);
        $fresh = $capacity->reserve('wordpress', 1048576, 20);
        self::assertSame(1, DB::table('chatgpt_file_admission_leases')->count());
        self::assertSame(1048576, (int) DB::table('chatgpt_file_admission_leases')->sum('reserved_bytes'));
        $fresh->release();
        self::assertSame(0, DB::table('chatgpt_file_admission_leases')->count());

        DB::table('chatgpt_file_admission_guard')->where('id', 1)->delete();
        try {
            app(ChatGptFileIngress::class)->download(self::FILE, 1048576, 30, 'wordpress');
            self::fail('A missing admission migration must fail closed.');
        } catch (OutboundRequestException $error) {
            self::assertSame('file_capacity_unavailable', $error->reason);
        }
        Http::assertNothingSent();
    }

    public function test_oversized_single_reservation_and_mode_budgets_are_bounded(): void
    {
        config()->set('bridge.file_input.capacity.max_reserved_bytes', 1048576);
        $capacity = app(ChatGptFileCapacity::class);
        self::assertSame(1048576, $capacity->limits()['max_reserved_bytes']);
        self::assertSame(2, $capacity->limits()['ssh_max_active']);

        try {
            app(ChatGptFileIngress::class)->download(self::FILE, 600000, 30, 'ssh');
            self::fail('One SSH transfer requires 2x the source maximum on local disk.');
        } catch (OutboundRequestException $error) {
            self::assertSame('file_capacity_exceeded', $error->reason);
        }
        Http::assertNothingSent();

        config()->set('bridge.file_input.capacity.max_reserved_bytes', PHP_INT_MAX);
        config()->set('bridge.file_input.capacity.max_active', PHP_INT_MAX);
        self::assertSame(536870912, $capacity->limits()['max_reserved_bytes']);
        self::assertSame(16, $capacity->limits()['max_active']);
    }
}
