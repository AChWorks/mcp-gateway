<?php

namespace App\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Str;

final class CorrelationId
{
    public const ATTRIBUTE = 'gateway_correlation_id';

    public const HEADER = 'X-Correlation-ID';

    public static function current(): string
    {
        if (app()->bound('request')) {
            $request = app('request');
            if ($request instanceof Request) {
                $value = $request->attributes->get(self::ATTRIBUTE);
                if (is_string($value) && Str::isUuid($value)) {
                    return $value;
                }
            }
        }

        return (string) Str::uuid();
    }
}
