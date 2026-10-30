<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Models\User;
use DomainException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;

/** Bind batch authority and audit attribution to the same current authenticated actor. */
final class AccessBatchGuard
{
    public static function actor(User $actor): User
    {
        $requestUser = app()->bound('request') ? app('request')->user() : null;
        if (! $requestUser instanceof User
            || (string) $requestUser->getKey() !== (string) $actor->getKey()
            || (string) Auth::id() !== (string) $actor->getKey()) {
            throw new AuthorizationException;
        }
        $fresh = User::query()->findOrFail($actor->getKey());
        Gate::forUser($fresh)->authorize(GatewayPermission::UsersManage->value);

        return $fresh;
    }

    public static function isOwner(User $user): bool
    {
        return $user->getRawOriginal('role') === GatewayRole::Owner->value;
    }

    public static function ssh(User $actor, bool $impact, bool $reviewed): void
    {
        if (! $impact) {
            return;
        }
        Gate::forUser($actor)->authorize(GatewayPermission::SecurityManage->value);
        if (! $reviewed) {
            throw new DomainException('ssh_confirmation_required');
        }
    }
}
