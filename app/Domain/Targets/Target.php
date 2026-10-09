<?php

namespace App\Domain\Targets;

use App\Support\Database\MicrosecondImmutableDateTimeCast;
use DomainException;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class Target extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'target_id',
        'display_name',
        'connector_type',
        'connection_state',
        'last_error_code',
        'last_tested_at',
        'connected_at',
        'last_success_at',
        'last_failure_at',
        'last_failure_code',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'connection_state' => TargetConnectionState::class,
            'last_tested_at' => MicrosecondImmutableDateTimeCast::class,
            'connected_at' => 'immutable_datetime',
            'last_success_at' => MicrosecondImmutableDateTimeCast::class,
            'last_failure_at' => MicrosecondImmutableDateTimeCast::class,
        ];
    }

    protected static function booted(): void
    {
        self::saving(static function (self $target): void {
            // Connector/Target identity may not be silently rebound by normal model updates.
            if ($target->exists && ($target->isDirty('id') || $target->isDirty('target_id') || $target->isDirty('connector_type'))) {
                throw new DomainException('Target identity and connector type are immutable; register a new Target.');
            }

            $id = (string) $target->getAttribute('target_id');
            if (strlen($id) > 64 || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/', $id) !== 1) {
                throw new DomainException('Target ID must be a lowercase slug of at most 64 characters.');
            }

            if (! in_array((string) $target->getAttribute('connector_type'), [
                'wp_ai_bridge',
                'ai_server_agent',
                'ssh_direct',
            ], true)) {
                throw new DomainException('Unsupported built-in Target connector type.');
            }
        });
    }

    /** @return HasMany<TargetCredential, $this> */
    public function credentials(): HasMany
    {
        return $this->hasMany(TargetCredential::class, 'target_record_id');
    }
}
