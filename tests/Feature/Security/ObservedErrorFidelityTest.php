<?php

namespace Tests\Feature\Security;

use App\Support\DiagnosticRedactor;
use App\Support\OperationDiagnostics;
use Tests\TestCase;

final class ObservedErrorFidelityTest extends TestCase
{
    public function test_original_unknown_code_message_paths_and_structured_cause_survive_secret_redaction(): void
    {
        $message = 'WP_Error provider/name:unknown-42 at /var/www/html/wp-content/uploads/logo.png '
            .'HTTP 422 https://blog.example.test/wp-json/abilities?token=SHOULD_NOT_ESCAPE&field=php_version '
            .'Bearer BEARER_SECRET_123 password=PASSWORD_SECRET_456';

        $safe = OperationDiagnostics::safeContext([
            'failure_origin' => 'downstream_mcp',
            'failure_stage' => 'operation',
            'source_error_code' => 'new-provider/permission.denied:42',
            'source_error_message' => $message,
            'source_error_details' => [
                'error' => [
                    'code' => 'provider/native-723',
                    'message' => 'Permission denied on /srv/wordpress/uploads/report.zip',
                    'password' => 'PASSWORD_IN_STRUCTURED_DATA',
                    'access_token' => 'ACCESS_TOKEN_IN_STRUCTURED_DATA',
                    'clientSecret' => 'CAMEL_CASE_SECRET',
                    'apiKey' => 'CAMEL_API_KEY_SECRET',
                ],
                'trace_file' => '/app/src/Provider.php',
                'line' => 82,
            ],
            'exception_class' => \RuntimeException::class,
        ]);

        self::assertSame('new-provider/permission.denied:42', $safe['source_error_code']);
        self::assertStringContainsString('provider/name:unknown-42', $safe['source_error_message']);
        self::assertStringContainsString('/var/www/html/wp-content/uploads/logo.png', $safe['source_error_message']);
        self::assertStringContainsString('HTTP 422', $safe['source_error_message']);
        self::assertStringContainsString('&field=php_version', $safe['source_error_message']);
        self::assertSame('provider/native-723', $safe['source_error_details']['error']['code']);
        self::assertSame('Permission denied on /srv/wordpress/uploads/report.zip',
            $safe['source_error_details']['error']['message']);
        self::assertSame('/app/src/Provider.php', $safe['source_error_details']['trace_file']);
        self::assertSame(\RuntimeException::class, $safe['exception_class']);

        $json = json_encode($safe, JSON_THROW_ON_ERROR);
        foreach (['SHOULD_NOT_ESCAPE', 'BEARER_SECRET_123', 'PASSWORD_SECRET_456',
            'PASSWORD_IN_STRUCTURED_DATA', 'ACCESS_TOKEN_IN_STRUCTURED_DATA',
            'CAMEL_CASE_SECRET', 'CAMEL_API_KEY_SECRET'] as $secret) {
            self::assertStringNotContainsString($secret, $json);
        }
        self::assertSame('[REDACTED]', $safe['source_error_details']['error']['access_token']);
        self::assertArrayNotHasKey('source_error_message_truncated', $safe);
        self::assertSame($safe, OperationDiagnostics::safeContext($safe));
    }

    public function test_quoted_password_with_spaces_is_fully_redacted_without_losing_surrounding_php_error(): void
    {
        $text = 'PHP fatal at /srv/blog/wp-content/plugins/sample.php: '
            .'password="secret with spaces and punctuation !@#" '
            .'failed connecting to https://provider.example.test/wp-json';

        $redacted = DiagnosticRedactor::text($text);
        self::assertStringContainsString('/srv/blog/wp-content/plugins/sample.php', $redacted);
        self::assertStringContainsString('https://provider.example.test/wp-json', $redacted);
        self::assertStringContainsString('password="[REDACTED]"', $redacted);
        self::assertStringNotContainsString('secret with spaces and punctuation', $redacted);
        self::assertSame($redacted, DiagnosticRedactor::text($redacted));
    }

    public function test_configurable_length_limit_marks_truncation_instead_of_silently_erasing_it(): void
    {
        config()->set('activity.diagnostic_message_max_bytes', 1024);
        $message = str_repeat('PHP provider validation: /var/www/html/wp-content/uploads/ -- ', 70);
        $safe = OperationDiagnostics::safeContext([
            'source_error_message' => $message,
            'source_error_code' => 'wordpress/very-specific-validation-code',
        ]);

        self::assertSame('wordpress/very-specific-validation-code', $safe['source_error_code']);
        self::assertSame(true, $safe['source_error_message_truncated']);
        self::assertSame(1024, strlen($safe['source_error_message']));
        self::assertStringStartsWith('PHP provider validation:', $safe['source_error_message']);
        self::assertSame($safe, OperationDiagnostics::safeContext($safe));
    }
}
