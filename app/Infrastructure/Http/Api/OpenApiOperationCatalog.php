<?php

namespace App\Infrastructure\Http\Api;

use InvalidArgumentException;
use JsonException;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * A reusable, pure OpenAPI operation reader. Specs are provider data only:
 * they never choose an outbound destination, credential, permission or PHP
 * executable. Unknown compatible new path/method entries need no code edits.
 */
final class OpenApiOperationCatalog
{
    /** @return array<string, mixed> */
    public function parse(string $document): array
    {
        try {
            $result = str_starts_with(ltrim($document), '{')
                ? json_decode($document, true, 128, JSON_THROW_ON_ERROR)
                : Yaml::parse($document);
        } catch (ParseException|JsonException $exception) {
            throw new InvalidArgumentException('API description cannot be parsed.', previous: $exception);
        }
        if (! is_array($result)
            || ! is_string($result['openapi'] ?? $result['swagger'] ?? null)
            || ! is_array($result['paths'] ?? null)) {
            throw new InvalidArgumentException('API description does not expose an OpenAPI path catalog.');
        }

        return $result;
    }

    /**
     * @param  array<string, mixed>  $spec
     * @return array{operations:list<array<string, mixed>>,next_offset:?int,total:int}
     */
    public function page(array $spec, int $offset = 0, int $limit = 20, ?string $search = null): array
    {
        if ($offset < 0 || $limit < 1 || $limit > 100) {
            throw new InvalidArgumentException('Invalid API catalog pagination.');
        }
        $matches = [];
        foreach ($spec['paths'] as $path => $definitions) {
            if (! is_string($path) || ! is_array($definitions)) {
                continue;
            }
            foreach ($definitions as $method => $operation) {
                if (! is_string($method) || ! is_array($operation)
                    || ! preg_match('/^(get|head|options|post|put|patch|delete|[a-z][a-z0-9-]*)$/D', $method)
                    || in_array($method, ['parameters', 'servers', 'summary', 'description'], true)) {
                    continue;
                }
                $summary = (string) ($operation['summary'] ?? '');
                $operationId = (string) ($operation['operationId'] ?? '');
                $tags = array_values(array_filter((array) ($operation['tags'] ?? []), 'is_string'));
                if ($search !== null && $search !== ''
                    && stripos($path.' '.$method.' '.$summary.' '.$operationId.' '.implode(' ', $tags), $search) === false) {
                    continue;
                }
                $parameters = [];
                foreach (array_merge(
                    is_array($definitions['parameters'] ?? null) ? $definitions['parameters'] : [],
                    is_array($operation['parameters'] ?? null) ? $operation['parameters'] : [],
                ) as $parameter) {
                    if (! is_array($parameter)) {
                        continue;
                    }
                    $resolved = $this->resolve($spec, $parameter);
                    $parameters[] = [
                        'name' => $resolved['name'] ?? null,
                        'in' => $resolved['in'] ?? null,
                        'required' => $resolved['required'] ?? false,
                        'schema' => $resolved['schema'] ?? null,
                    ];
                }
                $body = $this->resolve($spec, (array) ($operation['requestBody'] ?? []));
                $matches[] = [
                    'method' => strtoupper($method),
                    'path' => $path,
                    'operation_id' => $operationId !== '' ? $operationId : null,
                    'summary' => $summary,
                    'tags' => $tags,
                    'parameters' => $parameters,
                    'request_body' => $body !== [] ? [
                        'required' => $body['required'] ?? false,
                        'content' => $body['content'] ?? null,
                    ] : null,
                ];
            }
        }
        $total = count($matches);

        return [
            'operations' => array_slice($matches, $offset, $limit),
            'next_offset' => $total > $offset + $limit ? $offset + $limit : null,
            'total' => $total,
        ];
    }

    /** @param array<string,mixed> $spec
     * @param  array<string,mixed>  $entry
     * @return array<string,mixed>
     */
    private function resolve(array $spec, array $entry): array
    {
        $ref = $entry['$ref'] ?? null;
        if (! is_string($ref) || ! str_starts_with($ref, '#/components/')) {
            return $entry;
        }
        $parts = explode('/', substr($ref, 2));
        $value = $spec;
        foreach ($parts as $part) {
            $part = str_replace(['~1', '~0'], ['/', '~'], $part);
            if (! is_array($value) || ! array_key_exists($part, $value)) {
                return $entry;
            }
            $value = $value[$part];
        }

        return is_array($value) ? $value : $entry;
    }
}
