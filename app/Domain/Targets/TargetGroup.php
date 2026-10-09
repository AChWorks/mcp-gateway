<?php

namespace App\Domain\Targets;

use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

final class TargetGroup extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = ['name'];

    /** @return BelongsToMany<Target, $this> */
    public function targets(): BelongsToMany
    {
        return $this->belongsToMany(
            Target::class,
            'target_group_targets',
            'target_group_id',
            'target_record_id',
        );
    }

    /** @return BelongsToMany<User, $this> */
    public function users(): BelongsToMany
    {
        return $this->belongsToMany(
            User::class,
            'target_group_users',
            'target_group_id',
            'user_id',
        );
    }
}
