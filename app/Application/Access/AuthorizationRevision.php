<?php

namespace App\Application\Access;

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
