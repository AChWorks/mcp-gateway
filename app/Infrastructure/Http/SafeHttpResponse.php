<?php

namespace App\Infrastructure\Http;

use JsonException;

final readonly class SafeHttpResponse
{
    /** @param array<string, list<string>> $headers */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
    ) {}

    public function header(string $name): ?string
    {
        foreach ($this->headers as $header => $values) {
            if (strcasecmp($header, $name) === 0) {
                $value = $values[0] ?? null;

                return is_string($value) && $value !== '' ? $value : null;
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    public function json(): array
    {
        try {
            $decoded = json_decode($this->body, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new OutboundRequestException('invalid_json', 'Remote endpoint returned invalid JSON.');
        }

        if (! is_array($decoded)) {
            throw new OutboundRequestException('invalid_json', 'Remote endpoint returned invalid JSON.');
        }

        return $decoded;
    }
}
