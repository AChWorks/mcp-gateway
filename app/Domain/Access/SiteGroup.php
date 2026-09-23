<?php

namespace App\Domain\Access;

use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/** @property string $id */
final class SiteGroup extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = ['name'];

    /** @return BelongsToMany<Site, $this> */
    public function sites(): BelongsToMany
    {
        return $this->belongsToMany(
            Site::class,
            'site_group_sites',
            'site_group_id',
            'site_record_id',
        );
    }

    /** @return BelongsToMany<User, $this> */
    public function users(): BelongsToMany
    {
        return $this->belongsToMany(
            User::class,
            'site_group_users',
            'site_group_id',
            'user_id',
        );
    }
}
