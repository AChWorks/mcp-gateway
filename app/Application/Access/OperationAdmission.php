<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\OAuth\League\Repositories\AccessTokenRepository;
use App\Models\User;
use Closure;

/** Shared current-actor and positive-permission decision; no connector policy. */
final readonly class OperationAdmission
{
    public function __construct(
        private AccessControl $access,
        private AccessTokenRepository $tokens,
    ) {}

    /**
     * Only authenticated entry middleware installs request authority. Trusted
     * in-process callers supply an already resolved actor; deferred callers
     * supply their current persisted consent/attempt guard, not a live bearer.
     *
     * @param  (Closure():bool)|null  $attemptGuard
     */
    public function capture(User $user, ?Closure $attemptGuard = null): VerifiedExecutionContext
    {
        if ($attemptGuard !== null) {
            return VerifiedExecutionContext::deferred($user, $attemptGuard);
        }
        $context = request()->attributes->get(VerifiedExecutionContext::REQUEST_ATTRIBUTE);

        if ($context instanceof VerifiedExecutionContext) {
            return $context;
        }

        return app()->runningInConsole()
            ? VerifiedExecutionContext::local($user)
            : VerifiedExecutionContext::unverified($user);
    }

    public function currentActor(VerifiedExecutionContext $context, User $expected, bool $requiresAiAccess = false): ?User
    {
        if ($context->actorId !== (int) $expected->getKey()) {
            return null;
        }
        $user = User::query()->find($context->actorId);
        if (! $user instanceof User || ! $user->access_enabled || ($requiresAiAccess && ! $user->ai_access_enabled)) {
            return null;
        }
        $authorized = match ($context->channel) {
            'mcp' => $context->tokenId !== null && $context->authorizationId !== null && $context->clientId !== null
                && $context->profileKey !== null && $context->profileGeneration !== null
                && $context->authorizationId === $this->tokens->dispatchAuthorizationId(
                    $context->tokenId, $context->actorId, $context->clientId,
                    $context->profileKey, $context->profileGeneration,
                ),
            'web' => (int) request()->user()?->getAuthIdentifier() === $context->actorId,
            'deferred' => $context->attemptGuard !== null && ($context->attemptGuard)(),
            'local' => true,
            default => false,
        };

        return $authorized ? $user : null;
    }

    /**
     * @param  list<GatewayPermission>  $permissions
     * @return array<string,bool>
     */
    public function permissions(VerifiedExecutionContext $context, User $expected, Target $target, array $permissions, bool $requiresAiAccess = false): array
    {
        $user = $this->currentActor($context, $expected, $requiresAiAccess);

        return $user === null ? [] : $this->access->allowsTargetPermissions($user, $target, $permissions);
    }

    /** @param list<GatewayPermission> $permissions
     * @return Closure():bool
     */
    public function targetGuard(User $user, Target $target, array $permissions): Closure
    {
        $context = $this->capture($user);
        $entry = $this->access->allowsTargetPermissions($user, $target, $permissions);

        return function () use ($context, $user, $target, $permissions, $entry): bool {
            if ($permissions === [] || in_array(false, $entry, true)) {
                return false;
            }
            $fresh = Target::query()->find($target->getKey());
            if (! $fresh instanceof Target || $fresh->connector_type !== $target->connector_type) {
                return false;
            }
            $current = $this->permissions($context, $user, $fresh, $permissions);

            return count($current) === count($permissions) && ! in_array(false, $current, true);
        };
    }

    /** @return Closure():bool */
    public function globalGuard(User $user, GatewayPermission $permission): Closure
    {
        $context = $this->capture($user);
        $entry = $this->access->allows($user, $permission);

        return function () use ($context, $user, $permission, $entry): bool {
            $current = $entry ? $this->currentActor($context, $user) : null;

            return $current !== null && $this->access->allows($current, $permission);
        };
    }

    public function allows(VerifiedExecutionContext $context, User $expected, Target $target, GatewayPermission $permission, bool $requiresAiAccess = false): bool
    {
        return $this->permissions($context, $expected, $target, [$permission], $requiresAiAccess)[$permission->value] ?? false;
    }
}
