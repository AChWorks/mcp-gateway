<?php

namespace App\Infrastructure\Connectors\WpAiBridge;

use App\Domain\Targets\Target;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class WpAiBridgeTargetConfig extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'target_record_id',
        'base_url',
        'base_url_hash',
        'mcp_resource_url',
        'oauth_issuer_url',
        'oauth_authorization_url',
        'oauth_token_url',
        'oauth_revocation_url',
    ];

    /** @return BelongsTo<Target, $this> */
    public function target(): BelongsTo
    {
        return $this->belongsTo(Target::class, 'target_record_id');
    }
}
