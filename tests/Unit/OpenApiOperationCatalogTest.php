<?php

namespace Tests\Unit;

use App\Infrastructure\Http\Api\OpenApiOperationCatalog;
use InvalidArgumentException;
use Tests\TestCase;

final class OpenApiOperationCatalogTest extends TestCase
{
    public function test_openapi_yaml_and_json_discover_added_methods_without_server_tool_changes(): void
    {
        $yaml = <<<'YAML'
openapi: 3.0.3
info:
  title: Example API
  version: 1
paths:
  /domains:
    get:
      operationId: domains.list
      summary: List domains
      parameters:
        - $ref: '#/components/parameters/Page'
    post:
      operationId: domains.create
      summary: Create domain
  /new-service/v27/products/{id}:
    patch:
      operationId: new.products.update
      summary: Newly added path
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
components:
  parameters:
    Page:
      name: page
      in: query
      schema:
        type: integer
YAML;
        $catalog = new OpenApiOperationCatalog;
        $parsed = $catalog->parse($yaml);
        $first = $catalog->page($parsed, limit: 2);
        self::assertSame(3, $first['total']);
        self::assertSame(2, $first['next_offset']);
        self::assertSame('GET', $first['operations'][0]['method']);
        self::assertSame('page', $first['operations'][0]['parameters'][0]['name']);
        self::assertSame('POST', $first['operations'][1]['method']);

        $next = $catalog->page($parsed, offset: 2);
        self::assertSame('PATCH', $next['operations'][0]['method']);
        self::assertSame('/new-service/v27/products/{id}', $next['operations'][0]['path']);
        self::assertSame('status', array_key_first($next['operations'][0]['request_body']['content']['application/json']['schema']['properties']));
        self::assertNull($next['next_offset']);

        $filtered = $catalog->page($parsed, search: 'new.products.update');
        self::assertCount(1, $filtered['operations']);
        self::assertSame('PATCH', $filtered['operations'][0]['method']);

        $json = json_encode($parsed, JSON_THROW_ON_ERROR);
        self::assertSame($parsed, $catalog->parse($json));
    }

    public function test_openapi3_multipart_schema_references_expose_actual_field_names(): void
    {
        $source = <<<'YAML'
openapi: 3.0.0
paths:
  /domains/{domain}/dns-records/import:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              $ref: '#/components/schemas/DnsRecordImport'
components:
  schemas:
    DnsRecordImport:
      type: object
      properties:
        f_zone_file:
          type: string
          format: binary
YAML;
        $catalog = new OpenApiOperationCatalog;
        $operation = $catalog->page($catalog->parse($source))['operations'][0];
        self::assertSame('binary',
            $operation['request_body']['content']['multipart/form-data']['schema']['properties']['f_zone_file']['format']);
    }

    public function test_swagger2_body_and_form_data_are_exposed_without_endpoint_registrations(): void
    {
        $schema = <<<'JSON'
{
  "swagger": "2.0",
  "consumes": ["application/json"],
  "paths": {
    "/videos/{video}/audio-tracks": {
      "post": {
        "consumes": ["multipart/form-data"],
        "parameters": [
          {"$ref": "#/parameters/Video"},
          {"name": "lang", "in": "formData", "type": "string", "required": true},
          {"name": "audio_track", "in": "formData", "type": "file", "required": true}
        ]
      }
    },
    "/tags": {
      "post": {
        "consumes": ["application/x-www-form-urlencoded"],
        "parameters": [{"name": "title", "in": "formData", "type": "string", "required": true}]
      }
    },
    "/servers": {
      "post": {"parameters": [{"name": "payload", "in": "body", "required": true,
        "schema": {"$ref": "#/definitions/Server"}}]}
    }
  },
  "parameters": {"Video": {"name": "video", "in": "path", "required": true, "type": "string"}},
  "definitions": {"Server": {"type": "object"}}
}
JSON;
        $catalog = (new OpenApiOperationCatalog)->page((new OpenApiOperationCatalog)->parse($schema));
        self::assertSame(3, $catalog['total']);
        self::assertSame('video', $catalog['operations'][0]['parameters'][0]['name']);
        $upload = $catalog['operations'][0]['request_body'];
        self::assertTrue($upload['required']);
        self::assertSame('binary', $upload['content']['multipart/form-data']['schema']['properties']['audio_track']['format']);
        self::assertSame(['lang', 'audio_track'], $upload['content']['multipart/form-data']['schema']['required']);
        self::assertArrayHasKey('application/x-www-form-urlencoded', $catalog['operations'][1]['request_body']['content']);
        self::assertSame('object', $catalog['operations'][2]['request_body']['content']['application/json']['schema']['type']);
    }

    public function test_malformed_documents_rejected_and_search_results_are_data_only(): void
    {
        $catalog = new OpenApiOperationCatalog;
        foreach (['', 'not yaml', '{', '{"openapi":"3.0","paths":"not object"}'] as $text) {
            try {
                $catalog->parse($text);
                self::fail('Invalid description was accepted.');
            } catch (InvalidArgumentException) {
                // A malformed provider spec never becomes executable code.
            }
        }
        $parsed = $catalog->parse('{"openapi":"3.1.0","paths":{"/future":{"get":{"summary":"NEW"}}}}');
        self::assertSame('GET', $catalog->page($parsed)['operations'][0]['method']);
        $this->expectException(InvalidArgumentException::class);
        $catalog->page($parsed, limit: 101);
    }
}
