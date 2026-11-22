<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchCoordinator;
use App\Domain\Targets\Target;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/** Controlled metadata/journal scale, NEVER a claim of 1,000 real SSH hosts. */
final class TargetBatchCapacityFixtureTest extends TestCase
{
    use RefreshDatabase;

    /** @return iterable<string, array{int}> */
    public static function fleetSizes(): iterable
    {
        yield '100 selected Targets' => [100];
        yield '1000 selected Targets' => [1000];
    }

    #[DataProvider('fleetSizes')]
    public function test_explicit_fleet_preview_journal_pagination_and_cancel_have_bounded_query_growth(int $count): void
    {
        $actor = User::query()->create([
            'name' => 'Capacity Fixture Owner', 'email' => 'batch-capacity-fixture@example.test',
            'password' => 'StrongPassword!234', 'role' => 'owner',
            'target_scope_mode' => 'all', 'access_enabled' => true, 'ai_access_enabled' => true,
        ]);
        $ids = $this->seedIsolatedSshMetadata($count);
        $request = Request::create('/admin/target-batches/preview', 'POST');
        $request->setUserResolver(static fn (): User => $actor);
        $origin = app(DeferredBatchAuthority::class)->captureWeb($actor, $request);
        $core = app(TargetBatchCoordinator::class);
        $arguments = ['command' => 'printf metadata-only', 'timeout_seconds' => 10];
        DB::flushQueryLog();
        DB::enableQueryLog();
        try {
            $preview = $core->preview($actor, $origin, 'ssh.command.run', $ids,
                $arguments, 'concurrent', false, 4);
            $queries = count(DB::getQueryLog());
        } finally {
            DB::disableQueryLog();
            DB::flushQueryLog();
        }
        self::assertSame($count, $preview['selected_count']);
        self::assertSame($count, $preview['eligible_count']);
        self::assertCount($count, $preview['items']);
        // Database pages and per-connector queries grow with chunks, NOT one
        // authorization/configuration/credential query per selected Target.
        self::assertLessThan(50, $queries, 'Unexpected N+1 preview across selected Targets.');

        $requestId = (string) Str::uuid();
        $created = $core->create($actor, $origin, $requestId, 'ssh.command.run',
            $ids, $arguments, $preview['preview_token'], 'concurrent', false, 4);
        self::assertSame('queued', $created['status']);
        self::assertSame($count, DB::table('target_batch_items')->where('batch_id', $created['batch_id'])->count());
        $page = $core->status($actor, $origin, $created['batch_id'], 0, 100);
        self::assertCount(100, $page['items']);
        self::assertSame($count === 100 ? null : 100, $page['next_offset']);
        self::assertSame($created['batch_id'], $core->create($actor, $origin, $requestId,
            'ssh.command.run', $ids, $arguments, $preview['preview_token'],
            'concurrent', false, 4)['batch_id']);
        self::assertSame(1, DB::table('target_batches')->count());
        self::assertSame('canceled', $core->cancel($actor, $origin, $created['batch_id'])['status']);
        $final = $core->status($actor, $origin, $created['batch_id']);
        self::assertSame($count, $final['counts']['canceled']);
        self::assertSame(0, DB::table('target_batch_items')->where('batch_id', $created['batch_id'])
            ->whereNotNull('dispatch_attempt_id')->count(), 'Fixture must never cause remote dispatch.');
    }

    /** @return list<string> */
    private function seedIsolatedSshMetadata(int $count): array
    {
        $ids = [];
        $targets = [];
        $configs = [];
        $credentials = [];
        $now = now();
        $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('q', 32));
        for ($i = 0; $i < $count; $i++) {
            $record = (string) Str::ulid();
            $id = 'capacity-host-'.$i;
            $ids[] = $id;
            $targets[] = [
                'id' => $record, 'target_id' => $id, 'display_name' => 'Capacity Target '.$i,
                'connector_type' => 'ssh_direct', 'connection_state' => 'connected',
                'created_at' => $now, 'updated_at' => $now,
            ];
            $configs[] = [
                'id' => (string) Str::ulid(), 'target_record_id' => $record,
                'host' => 'capacity-'.$i.'.example.test', 'port' => 22,
                'username' => 'fixture', 'auth_method' => 'password', 'pinned_host_key' => $pin,
                'created_at' => $now, 'updated_at' => $now,
            ];
            $credentials[] = [
                'id' => (string) Str::ulid(), 'target_record_id' => $record,
                'connector_type' => 'ssh_direct', 'purpose' => 'ssh_auth',
                'encrypted_payload' => Crypt::encryptString('isolated-fixture-only-'.$i),
                'created_at' => $now, 'updated_at' => $now,
            ];
        }
        foreach (array_chunk($targets, 50) as $page) {
            DB::table('targets')->insert($page);
        }
        foreach (array_chunk($configs, 50) as $page) {
            DB::table('ssh_direct_target_configs')->insert($page);
        }
        foreach (array_chunk($credentials, 50) as $page) {
            DB::table('target_credentials')->insert($page);
        }

        return $ids;
    }
}
