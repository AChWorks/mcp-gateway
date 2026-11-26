<?php

namespace App\Domain\Targets;

use DomainException;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class TargetCredential extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'target_record_id',
        'connector_type',
        'purpose',
        'encrypted_payload',
    ];

    /** @var list<string> */
    protected $hidden = ['encrypted_payload'];

    protected static function booted(): void
    {
        self::saving(static function (self $credential): void {
            if ($credential->exists && (
                $credential->isDirty('target_record_id')
                || $credential->isDirty('connector_type')
                || $credential->isDirty('purpose')
            )) {
                throw new DomainException('Credential identity, connector and purpose cannot be reassigned.');
            }
            $target = Target::query()->find($credential->target_record_id);
            if (! $target instanceof Target
                || ! hash_equals((string) $target->connector_type, (string) $credential->connector_type)) {
                throw new DomainException('Credential connector type must match the exact registered Target.');
            }
        });
    }

    /**
     * Exact record/material snapshot for in-flight checks and credential editors.
     * This is not a semantic grant identity; ordinary reseal/refresh may change it.
     */
    public function materialFingerprint(): string
    {
        return hash('sha256', (string) $this->getKey()."\0".(string) $this->encrypted_payload);
    }

    /** @return BelongsTo<Target, $this> */
    public function target(): BelongsTo
    {
        return $this->belongsTo(Target::class, 'target_record_id');
    }
}
