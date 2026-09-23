<?php

namespace Tests\Feature\Sites;

use App\Application\Sites\SiteHealth;
use App\Domain\Sites\Site;
use App\Domain\Sites\SiteConnectionState;
use App\Domain\Sites\SiteHealthState;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class SiteHealthTest extends TestCase
{
    use RefreshDatabase;

    public function test_health_derivation_distinguishes_last_known_site_conditions(): void
    {
        config()->set('bridge.health.stale_after_hours', 24);
        $health = app(SiteHealth::class);
        $site = $this->site();

        self::assertSame(SiteHealthState::NeverConnected, $health->state($site));

        $health->recordOperationFailure($site, 'network_failure');
        self::assertSame(SiteHealthState::Unreachable, $health->state($site->refresh()));

        $site->forceFill(['connection_state' => SiteConnectionState::Connected])->save();
        $health->recordOperationSuccess($site);
        self::assertSame(SiteHealthState::Healthy, $health->state($site->refresh()));

        $this->travel(25)->hours();
        self::assertSame(SiteHealthState::Stale, $health->state($site->refresh()));

        $health->recordOperationFailure($site, 'incompatible_metadata');
        self::assertSame(SiteHealthState::Incompatible, $health->state($site->refresh()));

        $site->forceFill([
            'connection_state' => SiteConnectionState::ReconnectRequired,
            'last_error_code' => 'invalid_grant',
        ])->save();
        self::assertSame(SiteHealthState::ReconnectRequired, $health->state($site->refresh()));
    }

    public function test_unknown_and_recovery_order_use_microsecond_evidence(): void
    {
        $health = app(SiteHealth::class);
        $site = $this->site();
        $site->forceFill([
            'connection_state' => SiteConnectionState::Connected,
            'last_success_at' => CarbonImmutable::parse('2026-09-23 10:00:00.100000'),
            'last_failure_at' => CarbonImmutable::parse('2026-09-23 10:00:00.200000'),
            'last_failure_code' => 'outcome_unknown',
        ])->save();

        $unknown = $site->refresh();
        self::assertSame('2026-09-23 10:00:00.100000', $unknown->getRawOriginal('last_success_at'));
        self::assertSame('2026-09-23 10:00:00.200000', $unknown->getRawOriginal('last_failure_at'));
        self::assertSame(SiteHealthState::Unknown, $health->state($unknown));

        $unknown->forceFill([
            'last_success_at' => CarbonImmutable::parse('2026-09-23 10:00:00.300000'),
        ])->save();

        $recovered = $site->refresh();
        self::assertSame('2026-09-23 10:00:00.300000', $recovered->getRawOriginal('last_success_at'));
        self::assertSame(SiteHealthState::Healthy, $health->state($recovered));
    }

    public function test_successful_check_after_failure_stays_never_connected_without_stale_failure(): void
    {
        $health = app(SiteHealth::class);
        $site = $this->site();
        $site->forceFill([
            'last_tested_at' => CarbonImmutable::parse('2026-09-23 10:00:00.300000'),
            'last_error_code' => null,
            'last_failure_at' => CarbonImmutable::parse('2026-09-23 10:00:00.200000'),
            'last_failure_code' => 'network_failure',
        ])->save();

        $checked = $site->refresh();
        self::assertSame('2026-09-23 10:00:00.300000', $checked->getRawOriginal('last_tested_at'));
        self::assertSame(SiteHealthState::NeverConnected, $health->state($checked));
    }

    public function test_health_evidence_keeps_only_latest_bounded_success_and_failure_metadata(): void
    {
        $health = app(SiteHealth::class);
        $site = $this->site();

        $health->recordOperationFailure($site, 'NETWORK failure with unsafe text !');
        $failed = $site->refresh();
        self::assertNotNull($failed->last_failure_at);
        self::assertSame('network_failure_with_unsafe_text', $failed->last_failure_code);
        self::assertNull($failed->last_success_at);

        $health->recordOperationSuccess($failed);
        $succeeded = $site->refresh();
        self::assertNotNull($succeeded->last_success_at);
        self::assertSame('network_failure_with_unsafe_text', $succeeded->last_failure_code);
        self::assertCount(1, Site::query()->get());
    }

    private function site(): Site
    {
        $base = 'https://health.example.test';

        return Site::query()->create([
            'site_id' => 'health-site',
            'display_name' => 'Health site',
            'base_url' => $base,
            'base_url_hash' => hash('sha256', $base),
            'connector_type' => 'wp_ai_bridge',
            'mcp_resource_url' => $base.'/wp-json/wp-ai-bridge/v1/mcp',
            'oauth_issuer_url' => $base,
            'oauth_authorization_url' => $base.'/wp-ai-bridge/oauth/authorize',
            'oauth_token_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/token',
            'oauth_revocation_url' => $base.'/wp-json/wp-ai-bridge/v1/oauth/revoke',
            'connection_state' => SiteConnectionState::Disconnected,
        ]);
    }
}
