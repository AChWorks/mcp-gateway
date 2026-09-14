<?php

namespace App\Domain\Sites;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SiteOAuthFlow extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'site_record_id',
        'state_hash',
        'encrypted_context',
        'expires_at',
        'consumed_at',
    ];

    /** @var list<string> */
    protected $hidden = ['state_hash', 'encrypted_context'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'expires_at' => 'immutable_datetime',
            'consumed_at' => 'immutable_datetime',
        ];
    }

    /** @return BelongsTo<Site, $this> */
    public function site(): BelongsTo
    {
        return $this->belongsTo(Site::class, 'site_record_id');
    }
}
