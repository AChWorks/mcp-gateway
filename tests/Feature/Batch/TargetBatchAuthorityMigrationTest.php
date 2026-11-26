<?php

namespace Tests\Feature\Batch;

use App\Application\Batch\TargetBatchBinding;
use App\Application\Targets\SshTargetRegistration;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetCredential;
use App\Infrastructure\Connectors\SshDirect\SshTargetBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Tests\TestCase;

#[Group('database-concurrency')]
final class TargetBatchAuthorityMigrationTest extends TestCase
{
    use RefreshDatabase;

    // Migration fixtures must not share Laravel's cached schema state with
    // independent-process race tests that explicitly rebuild the database.
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function test_only_exact_never_dispatched_queued_authority_is_converted_without_rewriting_history(): void
    {
        $pin = 'ssh-ed25519 '.base64_encode(pack('N', 11).'ssh-ed25519'.pack('N', 32).str_repeat('K', 32));
        $ssh = app(SshTargetRegistration::class)->register(
            'migration-ssh', 'Migration SSH', 'ssh.example.test', 22, 'fixture',
            $pin, 'password', 'fixture-password', null,
        );
        $ssh->forceFill(['connection_state' => 'connected'])->save();
        $wp = $this->wordpress('migration-wp');
        $pending = $this->wordpress('migration-pending');
        $superseded = $this->wordpress('migration-superseded');
        $bindings = app(TargetBatchBinding::class);
        $expected = [];
        foreach ([$ssh, $wp, $pending, $superseded] as $target) {
            $target->refresh();
            $credential = TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
            $old = $this->predecessorHash($target, $credential);
            $new = $bindings->hash($target);
            self::assertIsString($new);
            self::assertNotSame($old, $new);
            if ($target->is($pending)) {
                // A legacy disconnect intent is an independent negative
                // authority witness, even if its saved health is Connected.
                DB::table('wp_ai_bridge_revocation_intents')->insert([
                    'id' => (string) Str::ulid(), 'target_record_id' => $target->getKey(),
                    'kind' => 'disconnect', 'created_at' => now(), 'updated_at' => now(),
                ]);
                self::assertNull($bindings->hash($target));
            }
            if ($target->is($superseded)) {
                DB::transaction(function () use ($target, $credential): void {
                    Target::query()->whereKey($target->getKey())->lockForUpdate()->sole();
                    $credential->supersedeAuthority();
                });
                self::assertNotSame($new, $bindings->hash($target));
            }
            foreach ([
                ['queued', $old, null, $target->target_id, true],
                ['queued', hash('sha256', 'obsolete-'.$old), null, $target->target_id, false],
                ['queued', $old, (string) Str::uuid(), $target->target_id, false],
                ['queued', $old, null, 'old-slug', false],
                ['dispatching', $old, (string) Str::uuid(), $target->target_id, false],
                ['completed', $old, (string) Str::uuid(), $target->target_id, false],
                ['outcome_unknown', $old, (string) Str::uuid(), $target->target_id, false],
            ] as [$status, $hash, $attempt, $slug, $eligible]) {
                $id = $this->item($target, $status, $hash, $attempt, $slug);
                $before = (array) DB::table('target_batch_items')->where('id', $id)->sole();
                if ($eligible && ! $target->is($pending) && ! $target->is($superseded)) {
                    $before['target_binding_hash'] = $new;
                }
                $expected[$id] = $before;
            }
        }
        $credentials = DB::table('target_credentials')->orderBy('id')->get()->map(fn ($row) => (array) $row)->all();
        $intents = DB::table('wp_ai_bridge_revocation_intents')->orderBy('id')->get()->map(fn ($row) => (array) $row)->all();
        $parents = DB::table('target_batches')->orderBy('id')->get()->map(fn ($row) => (array) $row)->all();
        $migration = require database_path('migrations/0001_01_01_000007_bind_queued_batches_to_credential_authority.php');
        for ($run = 0; $run < 2; $run++) {
            $migration->up();
            foreach ($expected as $id => $row) {
                self::assertSame($row, (array) DB::table('target_batch_items')->where('id', $id)->sole());
            }
            self::assertSame($credentials, DB::table('target_credentials')->orderBy('id')->get()->map(fn ($row) => (array) $row)->all());
            self::assertSame($intents, DB::table('wp_ai_bridge_revocation_intents')->orderBy('id')->get()->map(fn ($row) => (array) $row)->all());
            self::assertSame($parents, DB::table('target_batches')->orderBy('id')->get()->map(fn ($row) => (array) $row)->all());
        }
    }

    private function wordpress(string $slug): Target
    {
        $target = Target::query()->create([
            'target_id' => $slug, 'display_name' => $slug,
            'connector_type' => 'wp_ai_bridge', 'connection_state' => 'connected',
        ]);
        $base = 'https://'.$slug.'.example.test';
        $resource = $base.'/wp-json/wp-ai-bridge/v1/mcp';
        DB::table('wp_ai_bridge_target_configs')->insert([
            'id' => (string) Str::ulid(), 'target_record_id' => $target->getKey(),
            'base_url' => $base, 'base_url_hash' => hash('sha256', $base),
            'mcp_resource_url' => $resource, 'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/authorize', 'oauth_token_url' => $base.'/token',
            'oauth_revocation_url' => $base.'/revoke',
        ]);
        $credential = TargetCredential::query()->create([
            'target_record_id' => $target->getKey(), 'connector_type' => 'wp_ai_bridge',
            'purpose' => 'wordpress_oauth', 'encrypted_payload' => Crypt::encryptString('fixture-material'),
        ]);
        $client = 'https://gateway.example.test/oauth/client.json';
        DB::table('wp_ai_bridge_credential_metadata')->insert([
            'credential_id' => $credential->getKey(), 'client_id' => $client,
            'resource_url' => $resource, 'binding_hash' => hash('sha256', $target->getKey()."\0".$target->target_id."\0".$client."\0".$resource),
            'generation' => 7,
        ]);

        return $target;
    }

    /** Exact P0 format; independent test oracle, not a runtime fallback. */
    private function predecessorHash(Target $target, TargetCredential $credential): string
    {
        $parts = [(string) $target->getKey(), $target->target_id, $target->connector_type,
            (string) $target->relay_record_id, (string) $target->transport_revision];
        if ($target->connector_type === 'ssh_direct') {
            $parts = [...$parts, SshTargetBinding::hash($target, $target->sshConfig),
                (string) $credential->getKey(), $credential->purpose, hash('sha256', $credential->encrypted_payload)];
        } else {
            $config = DB::table('wp_ai_bridge_target_configs')->where('target_record_id', $target->getKey())->sole();
            $metadata = DB::table('wp_ai_bridge_credential_metadata')->where('credential_id', $credential->getKey())->sole();
            $parts = [...$parts, $config->base_url, $config->mcp_resource_url, $config->oauth_issuer_url, $config->oauth_token_url,
                (string) $credential->getKey(), $credential->purpose, $metadata->client_id, $metadata->resource_url, $metadata->binding_hash];
        }

        return hash('sha256', implode("\0", $parts));
    }

    private function item(Target $target, string $status, string $hash, ?string $attempt, string $slug): string
    {
        $batchId = (string) Str::ulid();
        DB::table('target_batches')->insert([
            'id' => $batchId, 'actor_user_id' => 1, 'source_channel' => 'web',
            'client_identity_hash' => hash('sha256', 'fixture-client'),
            'request_id' => (string) Str::uuid(), 'request_fingerprint' => hash('sha256', $batchId),
            'request_intent_hash' => hash('sha256', 'intent-'.$batchId),
            'capability_key' => $target->connector_type === 'ssh_direct' ? 'ssh.command.run' : 'wordpress.bridge.info',
            'arguments_ciphertext' => Crypt::encryptString('{}'),
            'execution_mode' => 'rolling', 'parallelism' => 1, 'target_count' => 1,
        ]);
        $id = (string) Str::ulid();
        DB::table('target_batch_items')->insert([
            'id' => $id, 'batch_id' => $batchId, 'target_record_id' => $target->getKey(),
            'target_id_snapshot' => $slug, 'connector_type_snapshot' => $target->connector_type,
            'target_binding_hash' => $hash, 'status' => $status, 'position' => 0,
            'dispatch_attempt_id' => $attempt, 'result_ciphertext' => $status === 'completed' ? Crypt::encryptString('known outcome') : null,
            'created_at' => now(), 'updated_at' => now(),
        ]);

        return $id;
    }
}
