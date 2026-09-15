<?php

namespace App\Domain\Sites;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SiteCredential extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'site_record_id',
        'client_id',
        'resource_url',
        'binding_hash',
        'encrypted_payload',
        'access_expires_at',
    ];

    /** @var list<string> */
    protected $hidden = ['encrypted_payload'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['access_expires_at' => 'immutable_datetime'];
    }

    /** @return BelongsTo<Site, $this> */
    public function site(): BelongsTo
    {
        return $this->belongsTo(Site::class, 'site_record_id');
    }
}
