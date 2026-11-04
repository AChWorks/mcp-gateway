<?php

namespace App\Infrastructure\Connectors\Relay;

use DomainException;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

final class ConnectionRelay extends Model
{
    use HasUlids;

    /** @var list<string> */
    protected $fillable = [
        'relay_id', 'display_name', 'control_host', 'control_port',
        'control_user', 'control_host_key', 'local_socks_port',
    ];

    protected function casts(): array
    {
        return [
            'control_port' => 'integer',
            'local_socks_port' => 'integer',
            'configuration_revision' => 'integer',
            'lifecycle_revision' => 'integer',
            'enabled' => 'boolean',
        ];
    }

    protected static function booted(): void
    {
        self::saving(static function (self $relay): void {
            // Only owner/password-gated service may modify a provisioned
            // routing identity, status or generation through a transaction.
            foreach ([
                'relay_id', 'control_host', 'control_port', 'control_user',
                'control_host_key', 'local_socks_port', 'enabled',
                'configuration_revision', 'lifecycle_revision',
            ] as $field) {
                if ($relay->exists && $relay->isDirty($field)) {
                    throw new DomainException('Connection Relay security binding requires Owner rotation workflow.');
                }
            }
        });
    }

    public function hostFingerprint(): string
    {
        return hash('sha256', implode("\0", [
            $this->relay_id, $this->control_host, (string) $this->control_port,
            $this->control_user, $this->control_host_key,
            (string) $this->local_socks_port, (string) $this->configuration_revision,
        ]));
    }
}
