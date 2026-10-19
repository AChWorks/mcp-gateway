<?php

namespace Tests\Unit;

use App\Application\Files\ChatGptFileIngress;
use Mcp\Capability\Discovery\SchemaValidator;
use PHPUnit\Framework\TestCase;

final class ChatGptFileIngressInputValidationTest extends TestCase
{
    public function test_fixed_rejection_classes_preserve_exact_existing_file_allowlist(): void
    {
        $accepted = [
            'file_id' => 'file_fixture',
            'download_url' => 'https://files.oaiusercontent.com/private/fixture?sig=never-log-this',
            'file_name' => 'qa.txt',
            'mime_type' => 'text/plain',
        ];
        self::assertNull(ChatGptFileIngress::inputValidationClass($accepted));
        self::assertTrue(ChatGptFileIngress::validFile($accepted));

        $cases = [
            'missing-id' => [['file_id' => null], 'file_id_invalid'],
            'empty-id' => [['file_id' => ''], 'file_id_invalid'],
            'oversized-id' => [['file_id' => str_repeat('i', 256)], 'file_id_invalid'],
            'missing-url' => [['download_url' => null], 'download_url_invalid'],
            'empty-url' => [['download_url' => ''], 'download_url_invalid'],
            'oversized-url' => [['download_url' => str_repeat('x', 8193)], 'download_url_invalid'],
            'http-url' => [['download_url' => 'http://files.oaiusercontent.com/private/fixture'], 'download_url_scheme_invalid'],
            'unknown-host' => [['download_url' => 'https://untrusted.example.test/private/file?token=never-log-this'], 'download_url_origin_denied'],
            'userinfo' => [['download_url' => 'https://user@files.oaiusercontent.com/private/file'], 'download_url_components_invalid'],
            'explicit-port' => [['download_url' => 'https://files.oaiusercontent.com:443/private/file'], 'download_url_components_invalid'],
            'fragment' => [['download_url' => 'https://files.oaiusercontent.com/private/file#fragment'], 'download_url_components_invalid'],
            'missing-path' => [['download_url' => 'https://files.oaiusercontent.com'], 'download_url_path_invalid'],
            'oversized-mime' => [['mime_type' => str_repeat('m', 256)], 'file_metadata_invalid'],
            'wrong-type-name' => [['file_name' => 5], 'file_metadata_invalid'],
        ];

        foreach ($cases as $name => [$overrides, $expected]) {
            $file = array_replace($accepted, $overrides);
            $reason = ChatGptFileIngress::inputValidationClass($file);
            self::assertSame($expected, $reason, $name);
            self::assertFalse(ChatGptFileIngress::validFile($file), $name);
            self::assertStringNotContainsString('never-log-this', (string) $reason);
            self::assertStringNotContainsString('untrusted.example.test', (string) $reason);
        }
    }

    public function test_actual_mcp_sdk_rejects_bare_file_strings_before_tool_handler(): void
    {
        $fileSchema = [
            'type' => 'object',
            'properties' => [
                'download_url' => ['type' => 'string'],
                'file_id' => ['type' => 'string'],
                'mime_type' => ['type' => 'string'],
                'file_name' => ['type' => 'string'],
            ],
            'required' => ['download_url', 'file_id'],
            'additionalProperties' => false,
        ];
        $schema = [
            'type' => 'object', 'properties' => ['file' => $fileSchema],
            'required' => ['file'], 'additionalProperties' => false,
        ];
        $validator = new SchemaValidator;

        foreach (['/mnt/data/qa.txt', 'file_test'] as $bare) {
            $errors = $validator->validateAgainstJsonSchema(['file' => $bare], $schema);
            self::assertNotEmpty($errors);
            self::assertSame('/file', $errors[0]['pointer']);
            self::assertSame('type', $errors[0]['keyword']);
        }

        self::assertSame([], $validator->validateAgainstJsonSchema(['file' => [
            'file_id' => 'file_test',
            'download_url' => 'https://files.oaiusercontent.com/private/file',
        ]], $schema));
    }
}
