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

        $escaped = 'PHP error at /var/www/site.php: password="SECRET_PREFIX '
            .'\"quoted\" SECRET_SUFFIX" while verifying user role';
        $escapedRedacted = DiagnosticRedactor::text($escaped);
        self::assertStringContainsString('/var/www/site.php', $escapedRedacted);
        self::assertStringContainsString('password="[REDACTED]"', $escapedRedacted);
        self::assertStringNotContainsString('SECRET_PREFIX', $escapedRedacted);
        self::assertStringNotContainsString('SECRET_SUFFIX', $escapedRedacted);
        self::assertSame($escapedRedacted, DiagnosticRedactor::text($escapedRedacted));
    }

    public function test_escaped_field_names_php_quoted_pairs_and_structured_keys_cannot_expose_secrets(): void
    {
        $embeddedJson = json_encode([
            'password' => 'ENCODED_PREFIX "inner quoted" ENCODED_SUFFIX',
        ], JSON_THROW_ON_ERROR);
        $escapedFieldNameJson = str_replace('"', '\\"', $embeddedJson);
        $message = 'Provider rejected /srv/wp/plugins/connector.php HTTP 422 '
            .$escapedFieldNameJson.' [\'api_key\' => \'PHP_QUOTED_SECRET\'] '
            .'with token=UNQUOTED_SECRET next_step=inspect';

        $safe = OperationDiagnostics::safeContext([
            'source_error_message' => $message,
            'source_error_details' => [
                'token=SECRET_IN_STRUCTURED_KEY' => 'SECRET_VALUE_FOR_KEY',
                'error' => [
                    'code' => 'native/unusual-422',
                    'message' => 'Validation failed at /var/www/blog/plugins/provider.php',
                    'password' => 'SECRET_IN_PASSWORD_VALUE',
                    'data' => [
                        'trace_file' => '/app/Provider.php',
                        'response_body' => 'SECRET_INSIDE_UNLABELLED_BODY',
                        'payload' => ['anonymous' => 'SECRET_IN_OPAQUE_PAYLOAD'],
                        'Bearer SECRET_IN_NESTED_KEY' => 'SECRET_IN_NESTED_KEY_VALUE',
                    ],
                ],
            ],
        ]);

        $serialized = json_encode($safe, JSON_THROW_ON_ERROR);
        foreach ([
            'ENCODED_PREFIX', 'ENCODED_SUFFIX', 'PHP_QUOTED_SECRET',
            'UNQUOTED_SECRET', 'SECRET_IN_STRUCTURED_KEY', 'SECRET_VALUE_FOR_KEY',
            'SECRET_IN_PASSWORD_VALUE', 'SECRET_INSIDE_UNLABELLED_BODY',
            'SECRET_IN_OPAQUE_PAYLOAD', 'SECRET_IN_NESTED_KEY',
            'SECRET_IN_NESTED_KEY_VALUE',
        ] as $secret) {
            self::assertStringNotContainsString($secret, $serialized);
        }
        self::assertStringContainsString('/srv/wp/plugins/connector.php', $safe['source_error_message']);
        self::assertStringContainsString('HTTP 422', $serialized);
        self::assertStringContainsString('next_step=inspect', $serialized);
        self::assertSame('native/unusual-422', $safe['source_error_details']['error']['code']);
        self::assertSame('/app/Provider.php',
            $safe['source_error_details']['error']['data']['trace_file']);
        self::assertSame('[REDACTED]',
            $safe['source_error_details']['error']['data']['response_body']);
        self::assertSame('[REDACTED]',
            $safe['source_error_details']['error']['data']['payload']);
        self::assertSame($safe, OperationDiagnostics::safeContext($safe));
        self::assertSame('[REDACTED: INVALID UTF-8]',
            DiagnosticRedactor::text("\xC3\x28"));
    }

    public function test_unusual_sensitive_structured_key_names_do_not_expose_embedded_secret_values(): void
    {
        $details = [
            'token_SECRET_IN_RAW_MAP_KEY' => 'secret associated value',
            'apiKey' => 'secret in ordinary credential value',
            'password' => 'secret password value',
            'source' => '/var/www/blog/wp-content/plugins/test.php',
        ];

        $safe = DiagnosticRedactor::value($details);
        $encoded = json_encode($safe, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('SECRET_IN_RAW_MAP_KEY', $encoded);
        self::assertStringNotContainsString('secret associated value', $encoded);
        self::assertStringNotContainsString('secret password value', $encoded);
        self::assertSame('[REDACTED]', $safe['apiKey']);
        self::assertSame('[REDACTED]', $safe['password']);
        self::assertSame('/var/www/blog/wp-content/plugins/test.php', $safe['source']);
        self::assertSame($safe, DiagnosticRedactor::value($safe));
    }

    public function test_ssh_passphrases_client_assertions_and_credential_bundles_are_masked(): void
    {
        $text = 'SSH handshake failed at /srv/connectors/Ssh.php '
            .'passphrase="SSH_PASSPHRASE_FIXTURE" '
            .'client_assertion=JWT_ASSERTION_FIXTURE '
            .'credentials="CREDENTIALS_FIXTURE"';

        $safeText = DiagnosticRedactor::text($text);
        $safeDetails = DiagnosticRedactor::value([
            'passphrase' => 'SSH_STRUCTURED_PASSPHRASE_FIXTURE',
            'clientAssertion' => 'STRUCTURED_ASSERTION_FIXTURE',
            'credentials' => ['nested' => 'STRUCTURED_CREDENTIALS_FIXTURE'],
            'file' => '/srv/connectors/Ssh.php',
        ]);

        $serialized = json_encode([$safeText, $safeDetails], JSON_THROW_ON_ERROR);
        foreach ([
            'SSH_PASSPHRASE_FIXTURE', 'JWT_ASSERTION_FIXTURE',
            'CREDENTIALS_FIXTURE', 'SSH_STRUCTURED_PASSPHRASE_FIXTURE',
            'STRUCTURED_ASSERTION_FIXTURE', 'STRUCTURED_CREDENTIALS_FIXTURE',
        ] as $secret) {
            self::assertStringNotContainsString($secret, $serialized);
        }
        self::assertStringContainsString('/srv/connectors/Ssh.php', $safeText);
        self::assertSame('[REDACTED]', $safeDetails['passphrase']);
        self::assertSame('[REDACTED]', $safeDetails['clientAssertion']);
        self::assertSame('[REDACTED]', $safeDetails['credentials']);
        self::assertSame($safeText, DiagnosticRedactor::text($safeText));
        self::assertSame($safeDetails, DiagnosticRedactor::value($safeDetails));
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
