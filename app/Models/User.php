<?php

namespace App\Models;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\TargetScopeMode;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

#[Fillable(['name', 'email', 'password', 'role', 'target_scope_mode', 'access_enabled'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable
{
    use Notifiable;

    /** @var array<string,mixed> */
    protected $attributes = [
        'role' => 'viewer',
        'target_scope_mode' => 'selected',
        'access_enabled' => true,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'role' => GatewayRole::class,
            'target_scope_mode' => TargetScopeMode::class,
            'access_enabled' => 'boolean',
        ];
    }
}
