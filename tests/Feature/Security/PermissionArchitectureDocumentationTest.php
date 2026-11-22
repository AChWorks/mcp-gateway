<?php

namespace Tests\Feature\Security;

use App\Application\Access\AccessControl;
use App\Domain\Access\GatewayPermission;
use App\Domain\Access\GatewayRole;
use Tests\TestCase;

/** Documentation points to the code-owned policy, not a copied permission table. */
final class PermissionArchitectureDocumentationTest extends TestCase
{
    public function test_architecture_links_to_authoritative_permission_policy_and_exhaustive_tests(): void
    {
        $architecture = (string) file_get_contents(base_path('docs/ARCHITECTURE.md'));

        // The source-of-truth roles, applicability and enforcement must be
        // discoverable without maintaining a second permission registry in Markdown.
        foreach ([
            GatewayRole::class => '../app/Domain/Access/GatewayRole.php',
            GatewayPermission::class => '../app/Domain/Access/GatewayPermission.php',
            AccessControl::class => '../app/Application/Access/AccessControl.php',
        ] as $class => $relativePath) {
            self::assertTrue(class_exists($class), 'Missing policy source class: '.$class);
            self::assertStringContainsString(']('.$relativePath.')', $architecture);
            self::assertFileExists(base_path(substr($relativePath, 3)));
        }

        self::assertStringContainsString('GatewayRole::permissions()', $architecture);
        self::assertStringContainsString('GatewayPermission::cases()', $architecture);
        self::assertStringContainsString('targetApplicability()', $architecture);
        self::assertStringContainsString('**Regression ownership:**', $architecture);
        self::assertStringContainsString('](../tests/Feature/Security/AccessControlTest.php)', $architecture);
        self::assertFileExists(base_path('tests/Feature/Security/AccessControlTest.php'));
    }
}
