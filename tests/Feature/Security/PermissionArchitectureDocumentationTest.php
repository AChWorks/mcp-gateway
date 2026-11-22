<?php

namespace Tests\Feature\Security;

use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use Tests\TestCase;

/** The #226 review matrix is a checkable snapshot, never a policy engine. */
final class PermissionArchitectureDocumentationTest extends TestCase
{
    public function test_owner_audit_matrix_tracks_every_defined_role_ceiling_and_connector(): void
    {
        $text = (string) file_get_contents(base_path('docs/ARCHITECTURE.md'));
        $start = strpos($text, '**Complete role × permission × applicable connector matrix**');
        $end = strpos($text, '**Registration, form, enforcement and test axes.**');
        self::assertIsInt($start);
        self::assertIsInt($end);
        self::assertGreaterThan($start, $end);
        $section = substr($text, $start, $end - $start);
        preg_match_all(
            '/^\| \\x60([a-z.]+)\\x60 \| (Gateway|Any Target|WordPress|ArvanCloud|SSH) \| ([✓–]) \| ([✓–]) \| ([✓–]) \| ([✓–]) \|$/mu',
            $section,
            $rows,
            PREG_SET_ORDER,
        );
        self::assertCount(count(GatewayPermission::cases()), $rows);
        $snapshot = [];
        foreach ($rows as $row) {
            self::assertArrayNotHasKey($row[1], $snapshot, 'Duplicate permission in canonical source audit.');
            $snapshot[$row[1]] = array_slice($row, 2);
        }
        foreach (GatewayPermission::cases() as $permission) {
            $connector = match ($permission->targetApplicability()) {
                null => 'Gateway',
                'any' => 'Any Target',
                'wp_ai_bridge' => 'WordPress',
                'arvancloud' => 'ArvanCloud',
                'ssh_direct' => 'SSH',
            };
            self::assertSame([
                $connector,
                ...array_map(static fn (GatewayRole $role): string => $role->allows($permission) ? '✓' : '–', GatewayRole::cases()),
            ], $snapshot[$permission->value] ?? null, 'Update the source-derived audit matrix for '.$permission->value);
        }
    }
}
