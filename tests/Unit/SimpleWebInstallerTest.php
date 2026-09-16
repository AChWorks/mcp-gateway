<?php

namespace Tests\Unit;

use App\Support\SimpleWebInstaller;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SimpleWebInstallerTest extends TestCase
{
    #[Test]
    public function it_accepts_a_canonical_https_origin_and_strong_admin_password(): void
    {
        $errors = SimpleWebInstaller::validateInput([
            'app_url' => 'https://gateway.example.com',
            'db_host' => '127.0.0.1',
            'db_port' => '3306',
            'db_database' => 'mcp_gateway',
            'db_username' => 'mcp_gateway',
            'db_password' => 'secret-database-password',
            'admin_name' => 'Admin',
            'admin_email' => 'admin@example.com',
            'admin_password' => 'StrongPassword!123',
            'admin_password_confirmation' => 'StrongPassword!123',
        ], 'gateway.example.com');

        self::assertSame([], $errors);
    }

    #[Test]
    public function it_rejects_non_https_or_cross_host_application_urls(): void
    {
        $httpErrors = SimpleWebInstaller::validateInput($this->validInput([
            'app_url' => 'http://gateway.example.com',
        ]), 'gateway.example.com');
        $otherHostErrors = SimpleWebInstaller::validateInput($this->validInput([
            'app_url' => 'https://other.example.com',
        ]), 'gateway.example.com');

        self::assertArrayHasKey('app_url', $httpErrors);
        self::assertArrayHasKey('app_url', $otherHostErrors);
    }

    #[Test]
    public function it_requires_the_same_admin_password_policy_as_the_cli_command(): void
    {
        $errors = SimpleWebInstaller::validateInput($this->validInput([
            'admin_password' => 'weakpassword',
            'admin_password_confirmation' => 'weakpassword',
        ]), 'gateway.example.com');

        self::assertArrayHasKey('admin_password', $errors);
    }

    #[Test]
    public function it_builds_a_production_environment_and_quotes_secrets(): void
    {
        $template = "APP_ENV=local\nAPP_KEY=\nAPP_DEBUG=true\nAPP_URL=http://127.0.0.1\nDB_CONNECTION=sqlite\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=old\nDB_USERNAME=old\nDB_PASSWORD=\nSESSION_DRIVER=file\nSESSION_ENCRYPT=true\nMCP_BOOTSTRAP_FIXTURE_ENABLED=true\nMCP_BOOTSTRAP_FIXTURE_TOKEN=test\n";

        $environment = SimpleWebInstaller::buildEnvironment($template, $this->validInput([
            'db_password' => 'a password#with special chars',
        ]), 'base64:test-key');

        self::assertStringContainsString("APP_ENV=production\n", $environment);
        self::assertStringContainsString("APP_DEBUG=false\n", $environment);
        self::assertStringContainsString("APP_URL=https://gateway.example.com\n", $environment);
        self::assertStringContainsString("APP_KEY=base64:test-key\n", $environment);
        self::assertStringContainsString("DB_CONNECTION=mysql\n", $environment);
        self::assertStringContainsString('DB_PASSWORD="a password#with special chars"', $environment);
        self::assertStringContainsString("SESSION_SECURE_COOKIE=true\n", $environment);
        self::assertStringContainsString("SESSION_HTTP_ONLY=true\n", $environment);
        self::assertStringContainsString("SESSION_SAME_SITE=lax\n", $environment);
        self::assertStringContainsString("MCP_BOOTSTRAP_FIXTURE_ENABLED=false\n", $environment);
        self::assertStringContainsString("MCP_BOOTSTRAP_FIXTURE_TOKEN=\"\"\n", $environment);
    }

    #[Test]
    public function it_detects_https_without_trusting_forwarded_headers(): void
    {
        self::assertTrue(SimpleWebInstaller::requestIsHttps(['HTTPS' => 'on', 'SERVER_PORT' => '443']));
        self::assertTrue(SimpleWebInstaller::requestIsHttps(['SERVER_PORT' => '443']));
        self::assertFalse(SimpleWebInstaller::requestIsHttps(['HTTP_X_FORWARDED_PROTO' => 'https', 'SERVER_PORT' => '80']));
    }

    #[Test]
    public function it_generates_a_valid_laravel_application_key(): void
    {
        $key = SimpleWebInstaller::generateApplicationKey();

        self::assertStringStartsWith('base64:', $key);
        $decoded = base64_decode(substr($key, 7), true);
        self::assertIsString($decoded);
        self::assertSame(32, strlen($decoded));
    }

    #[Test]
    public function it_locks_when_the_private_install_marker_exists(): void
    {
        $basePath = sys_get_temp_dir().'/mcp-installer-test-'.bin2hex(random_bytes(6));
        $markerPath = SimpleWebInstaller::installedMarkerPath($basePath);

        self::assertFalse(SimpleWebInstaller::isInstalled($basePath));
        mkdir(dirname($markerPath), 0700, true);
        file_put_contents($markerPath, '{}');

        try {
            self::assertTrue(SimpleWebInstaller::isInstalled($basePath));
        } finally {
            unlink($markerPath);
            rmdir(dirname($markerPath));
            rmdir(dirname(dirname($markerPath)));
            rmdir(dirname(dirname(dirname($markerPath))));
            rmdir($basePath);
        }
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function validInput(array $overrides = []): array
    {
        return [
            'app_url' => 'https://gateway.example.com',
            'db_host' => '127.0.0.1',
            'db_port' => '3306',
            'db_database' => 'mcp_gateway',
            'db_username' => 'mcp_gateway',
            'db_password' => 'secret-database-password',
            'admin_name' => 'Admin',
            'admin_email' => 'admin@example.com',
            'admin_password' => 'StrongPassword!123',
            'admin_password_confirmation' => 'StrongPassword!123',
            ...$overrides,
        ];
    }
}
