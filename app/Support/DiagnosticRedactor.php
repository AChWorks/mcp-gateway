<?php

namespace App\Support;

/**
 * Keep observed errors recognizable. Remove credentials, not diagnostic facts.
 *
 * This is defence in depth for permissioned diagnostics, not a justification
 * for exposing arbitrary remote payloads or bypassing existing Target scopes.
 */
final class DiagnosticRedactor
{
    public static function text(string $text): string
    {
        $text = preg_replace(
            '~-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----~s',
            '[REDACTED PRIVATE KEY]',
            $text,
        ) ?? $text;

        // Token schemes and explicit credential assignments in exceptions,
        // including URL queries. Keep the surrounding error/path/URL intact.
        $text = preg_replace(
            '~(?i)\b(Bearer|Basic)(\s+)[a-z0-9._\~+/=-]+~',
            '$1$2[REDACTED]',
            $text,
        ) ?? $text;

        $keys = '(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|secret|authorization|set[_-]?cookie|cookie|session[_-]?id|session)';

        $text = preg_replace(
            '~(?i)(\x22'.$keys.'\x22\s*:\s*\x22)(?:[^\x22\\\\]|\\\\.)*(\x22)~',
            '$1[REDACTED]$2',
            $text,
        ) ?? $text;

        // Quoted assignment values can contain spaces and punctuation. Mask
        // the entire value, not just its first word; remain idempotent.
        $text = preg_replace(
            '~(?is)(\b'.$keys.'\b\s*[:=]\s*)([\x22\x27])(?!\[REDACTED\])(?:\\\\.|(?!\2).)*\2~',
            '$1$2[REDACTED]$2',
            $text,
        ) ?? $text;

        $text = preg_replace(
            '~(?i)(\b'.$keys.'\b\s*[:=]\s*[\x22\x27]?)(?!\[REDACTED\]|(?:Bearer|Basic)\s+\[REDACTED\])[^\s\x22\x27,;&#}\]\)]+~',
            '$1[REDACTED]',
            $text,
        ) ?? $text;

        // Credentials embedded in URL userinfo, leaving host/path/query for
        // operators when those are needed to understand the failure.
        return preg_replace(
            '~(?i)\b(https?://)[^\s/@]+@~',
            '$1[REDACTED]@',
            $text,
        ) ?? $text;
    }

    public static function value(mixed $value, string $field = '', int $depth = 0): mixed
    {
        // Normalize the *field name only* to recognize camelCase secret keys;
        // never normalize the actual error code/message being diagnosed.
        $fieldName = strtolower(preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', $field) ?? $field);
        $fieldName = str_replace('-', '_', $fieldName);
        if (preg_match('~(?:^|_)(?:password|passwd|secret|token|authorization|cookie|credential|private_key|api_key|session_id)(?:$|_)~', $fieldName) === 1) {
            return '[REDACTED]';
        }

        if (is_string($value)) {
            return self::text($value);
        }

        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }

        if (! is_array($value)) {
            return '[UNSUPPORTED VALUE]';
        }

        if ($depth >= 7) {
            return ['_truncated' => 'nesting_depth'];
        }

        $result = [];
        foreach ($value as $key => $item) {
            if (count($result) >= 200) {
                $result['_truncated'] = 'entry_count';
                break;
            }

            $result[$key] = self::value($item, (string) $key, $depth + 1);
        }

        return $result;
    }
}
