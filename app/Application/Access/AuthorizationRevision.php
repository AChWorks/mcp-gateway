<?php

namespace App\Application\Access;

use App\Domain\Access\GatewayRole;

/**
 * Canonical optimistic authorization snapshot. A revision is not a grant,
 * authentication secret or CSRF token; Owner authorization remains mandatory.
 */
final class AuthorizationRevision
{
    /** @param list<string> $denials */
    public static function groupDenials(array $denials): string
    {
        return self::digest(['denied_permissions' => self::sorted($denials)]);
    }

    /**
     * @param  array{access_rule:string,denied_permissions:list<string>}  $rule
     */
    public static function targetRule(array $rule): string
    {
        return self::digest([
            'access_rule' => $rule['access_rule'],
            'denied_permissions' => self::sorted($rule['denied_permissions']),
        ]);
    }

    /**
     * Per-User Target editor revision. The user's Role changes which Denies
     * can be edited, even when the stored Target rule remains identical.
     * Bind the Role so an old Viewer form cannot clear an Administrator Deny
     * after promotion. The separate opt-in self-created scope and immutable
     * creator identity also affect effective inherited reachability; old
     * forms must never silently inherit a changed scope. Batch reachability
     * review retains targetRule()'s separate rule-only contract and live guards.
     *
     * @param  array{access_rule:string,denied_permissions:list<string>}  $rule
     */
    public static function userTargetRule(
        array $rule, GatewayRole $role, bool $selfCreatedScope, ?int $creatorUserId,
    ): string {
        return self::digest([
            'target_rule' => self::targetRule($rule),
            'user_role' => $role->value,
            'self_created_target_access' => $selfCreatedScope,
            'created_by_user_id' => $creatorUserId,
        ]);
    }

    /** @param list<string> $denials
     * @return list<string>
     */
    private static function sorted(array $denials): array
    {
        $normalized = array_values(array_unique($denials));
        sort($normalized, SORT_STRING);

        return $normalized;
    }

    /** @param array<string,mixed> $data */
    private static function digest(array $data): string
    {
        return hash('sha256', json_encode($data, JSON_THROW_ON_ERROR));
    }
}
