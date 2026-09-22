<?php

namespace App\Models;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

#[Fillable(['name', 'email', 'password', 'role', 'site_scope_mode', 'access_enabled'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable
{
    use Notifiable;

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
            'site_scope_mode' => SiteScopeMode::class,
            'access_enabled' => 'boolean',
        ];
    }
}
