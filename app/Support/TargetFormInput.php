<?php

namespace App\Support;

use Illuminate\Http\Request;

/**
 * Only allowlisted, non-secret form values may be restored after a redirect.
 * A URL containing opaque credentials or signed components must not enter
 * session old input, including when a connector reports a policy rejection.
 */
final class TargetFormInput
{
    /** @param list<string> $fields
     * @return array<string, mixed>
     */
    public static function replayable(Request $request, array $fields): array
    {
        $input = $request->only($fields);
        foreach ($input as $field => $value) {
            if (($field === 'url' || str_ends_with($field, '_url')) && ! self::safeUrl($value)) {
                unset($input[$field]);
            }
        }

        return $input;
    }

    private static function safeUrl(mixed $url): bool
    {
        if (! is_string($url) || $url === '' || preg_match('/[\\x00-\\x20\\x7f]/', $url) === 1) {
            return false;
        }

        $parts = parse_url($url);

        return is_array($parts)
            && strtolower((string) ($parts['scheme'] ?? '')) === 'https'
            && is_string($parts['host'] ?? null) && $parts['host'] !== ''
            && ! isset($parts['user']) && ! isset($parts['pass'])
            && ! isset($parts['query']) && ! isset($parts['fragment']);
    }
}
