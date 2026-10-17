<?php

namespace App\Support;

/**
 * Retain useful observed errors while removing identifiable secrets and opaque
 * payload fields. Unparseable redaction input must never fall back to raw data.
 */
final class DiagnosticRedactor
{
    public static function text(string $text): string
    {
        if (! mb_check_encoding($text, 'UTF-8')) {
            return '[REDACTED: INVALID UTF-8]';
        }

        foreach ([
            ['~-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----~s', '[REDACTED PRIVATE KEY]'],
            ['~(?i)\b(Bearer|Basic)(\s+)[a-z0-9._\~+/=-]+~', '$1$2[REDACTED]'],
            ['~(?i)\b(https?://)[^\s/@]+@~', '$1[REDACTED]@'],
        ] as [$pattern, $replacement]) {
            $redacted = preg_replace($pattern, $replacement, $text);
            if ($redacted === null) {
                return '[REDACTED: INVALID CONTENT]';
            }
            $text = $redacted;
        }

        // Match the *name and separator* first, then scan the value using its
        // actual quote/escape delimiter. This covers PHP 'key' => 'value',
        // JSON "key":"value", and JSON embedded as \"key\":\"value\".
        // A simple quoted-value regex can stop at an inner escaped quote and
        // inadvertently leave the remainder of the credential in the log.
        $keys = '(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|secret|authorization|set[_-]?cookie|cookie|session[_-]?id|session|credential)';
        $pattern = '~(?i)(?<![a-z0-9_-])(?:[\\\\]{0,4}[\x22\x27])?'.$keys.'(?:[\\\\]{0,4}[\x22\x27])?\s*(?::|=>|=)\s*~';

        $count = preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE);
        if ($count === false) {
            return '[REDACTED: INVALID CONTENT]';
        }

        $result = '';
        $cursor = 0;
        foreach ($matches[0] as [$prefix, $offset]) {
            if ($offset < $cursor) {
                continue;
            }

            $valueStart = $offset + strlen($prefix);
            [$replacement, $end] = self::maskAssignedValue($text, $valueStart);
            $result .= substr($text, $cursor, $valueStart - $cursor).$replacement;
            $cursor = $end;
        }

        return $result.substr($text, $cursor);
    }

    /**
     * @return array{string,int}
     */
    private static function maskAssignedValue(string $text, int $start): array
    {
        $length = strlen($text);
        if (substr($text, $start, 10) === '[REDACTED]') {
            return ['[REDACTED]', $start + 10];
        }
        if ($start >= $length) {
            return ['[REDACTED]', $length];
        }

        $slashes = 0;
        while ($start + $slashes < $length && $text[$start + $slashes] === '\\') {
            $slashes++;
        }
        $quotePos = $start + $slashes;
        $quote = $quotePos < $length ? $text[$quotePos] : '';
        if ($slashes <= 4 && ($quote === '"' || $quote === "'")) {
            $begin = $quotePos + 1;
            $scan = $begin;
            while (($end = strpos($text, $quote, $scan)) !== false) {
                $preceding = 0;
                for ($i = $end - 1; $i >= $begin && $text[$i] === '\\'; $i--) {
                    $preceding++;
                }
                // For plain quotes, backslash-escaped inner quotes cannot
                // terminate the value. For escaped JSON, an inner quoted
                // fragment carries more slashes than the enclosing delimiter.
                if (($slashes === 0 && $preceding % 2 === 0)
                    || ($slashes > 0 && $preceding === $slashes)) {
                    $delimiter = str_repeat('\\', $slashes).$quote;

                    return [$delimiter.'[REDACTED]'.$delimiter, $end + 1];
                }
                $scan = $end + 1;
            }

            // Unterminated quoted content: discard the tail rather than
            // risking disclosure from a guessed closing boundary.
            return [str_repeat('\\', $slashes).$quote.'[REDACTED]', $length];
        }

        // Unquoted assignments are delimited conservatively; an opaque
        // multiword payload must be explicitly quoted to establish its bounds.
        $end = $start + strcspn($text, " \t\r\n,;&#}])", $start);

        return ['[REDACTED]', $end];
    }

    public static function value(mixed $value, string $field = '', int $depth = 0): mixed
    {
        // Normalize field *names* only, not provider error codes/messages.
        $fieldName = strtolower(preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', $field) ?? $field);
        $fieldName = str_replace('-', '_', $fieldName);
        if (preg_match('~(?:^|_)(?:password|passwd|secret|token|authorization|cookie|credential|private_key|api_key|session_id|body|payload|raw_data|raw_request|raw_response|file_content|file_contents|content_base64|attachment|arguments|user_input|content|headers|file_bytes|raw_output)(?:$|_)~', $fieldName) === 1) {
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

            // Remote JSON object keys are untrusted too. A credential can
            // appear *inside the key* (e.g. token=SECRET or Bearer SECRET).
            // Mask both the affected key and its associated opaque value.
            $originalKey = (string) $key;
            $safeKey = is_int($key) ? $key : (strlen($originalKey) > 4096
                ? '[REDACTED: OVERSIZE KEY]' : self::text($originalKey));
            $keyWasRedacted = $safeKey !== $key;
            $result[$safeKey] = $keyWasRedacted ? '[REDACTED]'
                : self::value($item, $originalKey, $depth + 1);
        }

        return $result;
    }
}
