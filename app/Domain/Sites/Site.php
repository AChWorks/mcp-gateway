<?php

namespace App\Domain\Sites;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

final class Site extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'site_id',
        'display_name',
        'base_url',
        'base_url_hash',
        'connector_type',
        'mcp_resource_url',
        'oauth_issuer_url',
        'oauth_authorization_url',
        'oauth_token_url',
        'oauth_revocation_url',
        'connection_state',
        'last_error_code',
        'last_tested_at',
        'connected_at',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'connection_state' => SiteConnectionState::class,
            'last_tested_at' => 'immutable_datetime',
            'connected_at' => 'immutable_datetime',
        ];
    }

    /** @return HasOne<SiteCredential, $this> */
    public function credential(): HasOne
    {
        return $this->hasOne(SiteCredential::class, 'site_record_id');
    }

    /** @return HasMany<SiteOAuthFlow, $this> */
    public function oauthFlows(): HasMany
    {
        return $this->hasMany(SiteOAuthFlow::class, 'site_record_id');
    }
}
