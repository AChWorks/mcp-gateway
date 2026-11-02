<?php

namespace App\Infrastructure\Connectors\SshDirect;

use Illuminate\Database\Eloquent\Model;

/** Optional, explicit Owner configuration; absence means disabled. */
final class SshManagedReverseGateway extends Model
{
    protected $table = 'ssh_reverse_gateway_settings';

    public $incrementing = false;

    protected $keyType = 'int';

    protected $fillable = [
        'id', 'enabled', 'control_host', 'control_port', 'control_user',
        'control_host_key', 'revision',
    ];

    protected function casts(): array
    {
        return ['enabled' => 'boolean', 'control_port' => 'integer', 'revision' => 'integer'];
    }

    public static function active(): bool
    {
        return (bool) self::query()->whereKey(1)->where('enabled', true)->exists();
    }
}
