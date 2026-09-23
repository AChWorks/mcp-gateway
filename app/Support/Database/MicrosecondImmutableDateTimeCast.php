<?php

namespace App\Support\Database;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * Preserve microsecond ordering for bounded site-health evidence.
 *
 * @implements CastsAttributes<CarbonImmutable, DateTimeInterface|string>
 */
final class MicrosecondImmutableDateTimeCast implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?CarbonImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        if ($value instanceof DateTimeInterface) {
            return CarbonImmutable::instance($value);
        }

        if (! is_string($value)) {
            throw new InvalidArgumentException(sprintf('%s must contain a database datetime string.', $key));
        }

        return CarbonImmutable::parse($value);
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if ($value instanceof DateTimeInterface) {
            $date = CarbonImmutable::instance($value);
        } elseif (is_string($value)) {
            $date = CarbonImmutable::parse($value);
        } else {
            throw new InvalidArgumentException(sprintf('%s must be a date/time value.', $key));
        }

        return $date->format('Y-m-d H:i:s.u');
    }
}
