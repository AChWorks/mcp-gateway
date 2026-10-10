<?php

namespace Tests\Feature\Migration;

use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Domain\Targets\TargetCredential;
use App\Domain\Targets\TargetGroup;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetConfig;
use DomainException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class TargetDomainFoundationTest extends TestCase
{
    use RefreshDatabase;

    public function test_three_supported_connector_identities_are_stable_and_wp_details_stay_connector_owned(): void
    {
        $wp = Target::query()->create([
            'target_id' => 'wordpress-main',
            'display_name' => 'WordPress',
            'connector_type' => 'wp_ai_bridge',
        ]);
        $agent = Target::query()->create([
            'target_id' => 'linux-agent',
            'display_name' => 'Agent',
            'connector_type' => 'ai_server_agent',
        ]);
        $ssh = Target::query()->create([
            'target_id' => 'server-ssh',
            'display_name' => 'Remote SSH',
            'connector_type' => 'ssh_direct',
        ]);

        self::assertSame(TargetConnectionState::Disconnected, $wp->refresh()->connection_state);
        self::assertSame('wp_ai_bridge', $wp->connector_type);
        self::assertSame('ai_server_agent', $agent->connector_type);
        self::assertSame('ssh_direct', $ssh->connector_type);
        self::assertNull($wp->getAttribute('base_url'));
        self::assertNull($agent->getAttribute('base_url'));
        self::assertNull($ssh->getAttribute('mcp_resource_url'));

        WpAiBridgeTargetConfig::query()->create([
            'target_record_id' => $wp->getKey(),
            'base_url' => 'https://wordpress.example.test',
            'base_url_hash' => hash('sha256', 'https://wordpress.example.test'),
            'mcp_resource_url' => 'https://wordpress.example.test/mcp',
            'oauth_issuer_url' => 'https://wordpress.example.test',
            'oauth_authorization_url' => 'https://wordpress.example.test/oauth/authorize',
            'oauth_token_url' => 'https://wordpress.example.test/oauth/token',
            'oauth_revocation_url' => 'https://wordpress.example.test/oauth/revoke',
        ]);
        $config = WpAiBridgeTargetConfig::query()->sole();
        self::assertSame($wp->getKey(), $config->target->getKey());
        self::assertNull($agent->refresh()->getAttribute('base_url'));
    }

    public function test_public_target_identity_and_connector_type_cannot_be_silently_rebound(): void
    {
        $target = Target::query()->create([
            'target_id' => 'original-target',
            'display_name' => 'Original',
            'connector_type' => 'ssh_direct',
        ]);

        $target->display_name = 'Renamed';
        $target->save();
        self::assertSame('Renamed', $target->refresh()->display_name);

        try {
            $target->target_id = 'replacement-target';
            $target->save();
            self::fail('Target slug rebind succeeded.');
        } catch (DomainException $exception) {
            self::assertStringContainsString('immutable', $exception->getMessage());
        }

        $target->refresh();
        try {
            $target->connector_type = 'ai_server_agent';
            $target->save();
            self::fail('Target connector reassignment succeeded.');
        } catch (DomainException $exception) {
            self::assertStringContainsString('immutable', $exception->getMessage());
        }

        self::assertSame('ssh_direct', $target->fresh()->connector_type);
        self::assertSame('original-target', $target->fresh()->target_id);
    }

    public function test_unregistered_connector_and_invalid_public_slug_are_rejected(): void
    {
        foreach ([
            ['Invalid Target', 'ssh_direct'],
            ['valid-target', 'arbitrary_plugin'],
            [str_repeat('a', 65), 'wp_ai_bridge'],
        ] as [$id, $connector]) {
            try {
                Target::query()->create([
                    'target_id' => $id,
                    'display_name' => 'Invalid',
                    'connector_type' => $connector,
                ]);
                self::fail('Unsafe Target was created.');
            } catch (DomainException) {
                // The model must reject unsupported identity before persistence.
            }
        }

        self::assertSame(0, Target::query()->count());
    }

    public function test_generic_target_group_and_credential_are_scoped_and_credential_is_hidden(): void
    {
        $target = Target::query()->create([
            'target_id' => 'credential-target',
            'display_name' => 'Server',
            'connector_type' => 'ssh_direct',
        ]);
        $group = TargetGroup::query()->create(['name' => 'Operator group']);
        $group->targets()->attach($target->getKey());

        self::assertSame($target->getKey(), $group->targets()->sole()->getKey());

        $credential = TargetCredential::query()->create([
            'target_record_id' => $target->getKey(),
            'connector_type' => 'ssh_direct',
            'purpose' => 'remote_ssh',
            'encrypted_payload' => 'encrypted-placeholder-secret',
        ]);
        self::assertSame('remote_ssh', $target->credentials()->sole()->purpose);
        self::assertSame($target->getKey(), $credential->target->getKey());
        self::assertStringNotContainsString('encrypted-placeholder-secret', (string) json_encode($credential->toArray()));

        try {
            TargetCredential::query()->create([
                'target_record_id' => $target->getKey(),
                'connector_type' => 'ai_server_agent',
                'purpose' => 'remote_ssh',
                'encrypted_payload' => 'unsafe-cross-connector',
            ]);
            self::fail('Cross-connector credential binding was accepted.');
        } catch (DomainException $exception) {
            self::assertStringContainsString('must match', $exception->getMessage());
        }
        self::assertSame(1, TargetCredential::query()->count());
    }
}
