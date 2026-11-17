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
