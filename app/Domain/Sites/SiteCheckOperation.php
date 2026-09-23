<?php

namespace App\Domain\Sites;

use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class SiteCheckOperation extends Model
{
    use HasUuids;

    /** @var list<string> */
    protected $fillable = [
        'creator_user_id',
        'idempotency_key',
        'active_slot',
        'status',
        'started_at',
        'completed_at',
    ];

    /** @return array<string,string> */
    protected function casts(): array
    {
        return [
            'active_slot' => 'integer',
            'status' => SiteCheckOperationStatus::class,
            'started_at' => 'immutable_datetime',
            'completed_at' => 'immutable_datetime',
        ];
    }

    public function statusValue(): SiteCheckOperationStatus
    {
        $status = $this->getAttribute('status');

        return $status instanceof SiteCheckOperationStatus
            ? $status
            : SiteCheckOperationStatus::from((string) $status);
    }

    /** @return BelongsTo<User, $this> */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'creator_user_id');
    }

    /** @return HasMany<SiteCheckOperationTarget, $this> */
    public function targets(): HasMany
    {
        return $this->hasMany(SiteCheckOperationTarget::class, 'operation_id');
    }
}
