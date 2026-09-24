<?php

namespace Tests\Unit\Domain\Access;

use App\Domain\Access\GatewayPermission;
use PHPUnit\Framework\TestCase;

final class GatewayPermissionTest extends TestCase
{
    public function test_every_permission_has_human_readable_metadata(): void
    {
        foreach (GatewayPermission::cases() as $permission) {
            self::assertNotSame('', trim($permission->title()), $permission->value);
            self::assertNotSame('', trim($permission->description()), $permission->value);
            self::assertContains($permission->scopeLabel(), ['Gateway-wide', 'Site-scoped']);
        }
    }

    public function test_site_remove_metadata_explains_effective_scope_instead_of_creation_ownership(): void
    {
        $permission = GatewayPermission::SitesRemove;

        self::assertSame('Remove sites', $permission->title());
        self::assertSame('Site-scoped', $permission->scopeLabel());
        self::assertTrue($permission->isSiteScoped());
        self::assertStringContainsString('effective site scope', $permission->description());
        self::assertStringContainsString('not limited to sites the user created', $permission->description());
    }

    public function test_site_create_is_gateway_wide_but_documents_selected_scope_auto_inclusion(): void
    {
        $permission = GatewayPermission::SitesCreate;

        self::assertSame('Gateway-wide', $permission->scopeLabel());
        self::assertFalse($permission->isSiteScoped());
        self::assertStringContainsString('automatically added', $permission->description());
    }
}
