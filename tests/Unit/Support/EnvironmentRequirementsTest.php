<?php

namespace Tests\Unit\Support;

use App\Support\EnvironmentRequirements;
use PHPUnit\Framework\TestCase;

final class EnvironmentRequirementsTest extends TestCase
{
    public function test_current_runtime_meets_required_php_extensions_with_mysql_and_a_valid_key(): void
    {
        $requirements = new EnvironmentRequirements;
        $key = 'base64:'.base64_encode(str_repeat('k', 32));
        $checks = $requirements->checks('mysql', $key, 'AES-256-CBC');

        self::assertNotContains(false, $checks, true);
        self::assertFalse($requirements->checks('sqlite', $key, 'AES-256-CBC')['MySQL is the configured database driver']);
        self::assertFalse($requirements->checks('mysql', null, 'AES-256-CBC')['Valid Laravel encryption key']);
        self::assertFalse($requirements->checks('mysql', 'not-a-valid-key', 'AES-256-CBC')['Valid Laravel encryption key']);
    }
}
