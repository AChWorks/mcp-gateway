<?php

namespace App\Domain\Sites;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

final class SiteRevocationIntent extends Model
{
    use HasUlids;

    public const KIND_DISCONNECT = 'disconnect';

    public const KIND_REMOVE = 'remove';

    /** @var list<string> */
    protected $fillable = [
        'site_record_id',
        'kind',
    ];
}
