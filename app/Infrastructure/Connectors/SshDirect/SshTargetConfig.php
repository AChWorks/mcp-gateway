<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;
use DomainException;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SshTargetConfig extends Model
{
    use HasUlids;

    protected $table = 'ssh_direct_target_configs';

    /** @var list<string> */
    protected $fillable = [
        'target_record_id', 'host', 'port', 'username', 'auth_method',
        'pinned_host_key', 'observed_peer_ip', 'observed_at',
    ];

    protected function casts(): array
    {
        return ['port' => 'integer', 'observed_at' => 'immutable_datetime'];
    }

    protected static function booted(): void
    {
        self::saving(static function (self $config): void {
            // Endpoint, user, authentication type and trusted key are a
            // single security binding. Rotation requires a separate workflow.
            foreach (['target_record_id', 'host', 'port', 'username', 'auth_method', 'pinned_host_key'] as $field) {
                if ($config->exists && $config->isDirty($field)) {
                    throw new DomainException('SSH endpoint or trust binding cannot be silently changed.');
                }
            }
        });
    }

    /** @return BelongsTo<Target, $this> */
    public function target(): BelongsTo
    {
        return $this->belongsTo(Target::class, 'target_record_id');
    }

    public function endpoint(): SshRegisteredEndpoint
    {
        return SshRegisteredEndpoint::fromInput($this->host, $this->port, $this->username);
    }
}
