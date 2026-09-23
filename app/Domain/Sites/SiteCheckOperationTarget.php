<?php

namespace App\Domain\Sites;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SiteCheckOperationTarget extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'operation_id',
        'site_record_id',
        'position',
        'site_id_snapshot',
        'display_name_snapshot',
        'status',
        'attempts',
        'attempt_token',
        'error_code',
        'started_at',
        'finished_at',
    ];

    /** @return array<string,string> */
    protected function casts(): array
    {
        return [
            'position' => 'integer',
            'status' => SiteCheckTargetStatus::class,
            'attempts' => 'integer',
            'started_at' => 'immutable_datetime',
            'finished_at' => 'immutable_datetime',
        ];
    }

    public function statusValue(): SiteCheckTargetStatus
    {
        $status = $this->getAttribute('status');

        return $status instanceof SiteCheckTargetStatus
            ? $status
            : SiteCheckTargetStatus::from((string) $status);
    }

    /** @return BelongsTo<SiteCheckOperation, $this> */
    public function operation(): BelongsTo
    {
        return $this->belongsTo(SiteCheckOperation::class, 'operation_id');
    }

    /** @return BelongsTo<Site, $this> */
    public function site(): BelongsTo
    {
        return $this->belongsTo(Site::class, 'site_record_id');
    }
}
