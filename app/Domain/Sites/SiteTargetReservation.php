<?php

namespace App\Domain\Sites;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SiteTargetReservation extends Model
{
    protected $primaryKey = 'target_hash';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = [
        'target_hash',
        'target_url',
        'owner_site_id',
        'site_record_id',
    ];

    /** @return BelongsTo<Site, $this> */
    public function site(): BelongsTo
    {
        return $this->belongsTo(Site::class, 'site_record_id');
    }
}
