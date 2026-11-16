<?php

namespace App\Infrastructure\Connectors\ArvanCloud;

use App\Domain\Targets\Target;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class ArvanApiTargetConfig extends Model
{
    use HasUlids;

    protected $table = 'arvan_api_target_configs';

    /** @var list<string> */
    protected $fillable = ['target_record_id', 'base_url', 'spec_url', 'probe_path'];

    /** @return BelongsTo<Target, $this> */
    public function target(): BelongsTo
    {
        return $this->belongsTo(Target::class, 'target_record_id');
    }
}
