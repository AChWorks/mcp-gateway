<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Domain\Sites\Site;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;

final readonly class AccessControl
{
    public function allows(User $user, GatewayPermission $permission, ?Site $site = null): bool
    {
        $role = $this->role($user);

        if (! $this->globalAllows($user, $role, $permission)) {
            return false;
        }

        if (! $site instanceof Site || $role === GatewayRole::Owner) {
            return true;
        }

        if (! $this->siteIsInScope($user, $site)) {
            return false;
        }

        return ! DB::table('user_site_permission_denials')
            ->where('user_id', $user->getKey())
            ->where('site_record_id', $site->getKey())
            ->where('permission', $permission->value)
            ->exists();
    }

    /**
     * Applies principal site membership only. Functional permission is deliberately separate so
     * a selected site can be write-only, read-only, or otherwise narrowed by capability.
     *
     * @param  Builder<Site>  $query
     * @return Builder<Site>
     */
    public function scopePrincipalSites(Builder $query, User $user): Builder
    {
        $role = $this->role($user);

        if (! (bool) $user->getAttribute('access_enabled') || ! $role instanceof GatewayRole) {
            return $query->whereRaw('1 = 0');
        }

        if ($role === GatewayRole::Owner) {
            return $query;
        }

        $scope = $this->scopeMode($user);
        if (! $scope instanceof SiteScopeMode) {
            return $query->whereRaw('1 = 0');
        }

        if ($scope === SiteScopeMode::Selected) {
            return $query->whereExists(function ($subquery) use ($user): void {
                $subquery
                    ->selectRaw('1')
                    ->from('user_site_access')
                    ->whereColumn('user_site_access.site_record_id', 'sites.id')
                    ->where('user_site_access.user_id', $user->getKey())
                    ->where('user_site_access.allowed', true);
            });
        }

        return $query->whereNotExists(function ($subquery) use ($user): void {
            $subquery
                ->selectRaw('1')
                ->from('user_site_access')
                ->whereColumn('user_site_access.site_record_id', 'sites.id')
                ->where('user_site_access.user_id', $user->getKey())
                ->where('user_site_access.allowed', false);
        });
    }

    /**
     * @param  Builder<Site>  $query
     * @return Builder<Site>
     */
    public function scopeSites(
        Builder $query,
        User $user,
        GatewayPermission $permission = GatewayPermission::SitesView,
    ): Builder {
        $role = $this->role($user);

        if (! $this->globalAllows($user, $role, $permission)) {
            return $query->whereRaw('1 = 0');
        }

        $query = $this->scopePrincipalSites($query, $user);

        if ($role === GatewayRole::Owner) {
            return $query;
        }

        return $query->whereNotExists(function ($subquery) use ($user, $permission): void {
            $subquery
                ->selectRaw('1')
                ->from('user_site_permission_denials')
                ->whereColumn('user_site_permission_denials.site_record_id', 'sites.id')
                ->where('user_site_permission_denials.user_id', $user->getKey())
                ->where('user_site_permission_denials.permission', $permission->value);
        });
    }

    public function hasAllSiteScope(User $user): bool
    {
        if (! (bool) $user->getAttribute('access_enabled')) {
            return false;
        }

        $role = $this->role($user);
        if ($role === GatewayRole::Owner) {
            return true;
        }

        return $role instanceof GatewayRole
            && $this->scopeMode($user) === SiteScopeMode::All;
    }

    public function includeCreatedSite(User $user, Site $site): void
    {
        $role = $this->role($user);

        if ($role === GatewayRole::Owner || $this->scopeMode($user) === SiteScopeMode::All) {
            return;
        }

        if (! $role instanceof GatewayRole || $this->scopeMode($user) !== SiteScopeMode::Selected) {
            return;
        }

        DB::table('user_site_access')->updateOrInsert(
            [
                'user_id' => $user->getKey(),
                'site_record_id' => $site->getKey(),
            ],
            [
                'allowed' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        );
    }

    private function globalAllows(
        User $user,
        ?GatewayRole $role,
        GatewayPermission $permission,
    ): bool {
        if (! (bool) $user->getAttribute('access_enabled')
            || ! $role instanceof GatewayRole
            || ! $role->allows($permission)) {
            return false;
        }

        if ($role === GatewayRole::Owner) {
            return true;
        }

        return ! DB::table('user_permission_denials')
            ->where('user_id', $user->getKey())
            ->where('permission', $permission->value)
            ->exists();
    }

    private function siteIsInScope(User $user, Site $site): bool
    {
        $scope = $this->scopeMode($user);
        if (! $scope instanceof SiteScopeMode) {
            return false;
        }

        $explicit = DB::table('user_site_access')
            ->where('user_id', $user->getKey())
            ->where('site_record_id', $site->getKey())
            ->value('allowed');

        if ($scope === SiteScopeMode::Selected) {
            return $explicit !== null && (bool) $explicit;
        }

        return $explicit === null || (bool) $explicit;
    }

    private function role(User $user): ?GatewayRole
    {
        $role = $user->getAttribute('role');

        if ($role instanceof GatewayRole) {
            return $role;
        }

        return is_string($role) ? GatewayRole::tryFrom($role) : null;
    }

    private function scopeMode(User $user): ?SiteScopeMode
    {
        $scope = $user->getAttribute('site_scope_mode');

        if ($scope instanceof SiteScopeMode) {
            return $scope;
        }

        return is_string($scope) ? SiteScopeMode::tryFrom($scope) : null;
    }
}
