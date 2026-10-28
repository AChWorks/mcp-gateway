<?php

namespace App\Application\Targets;

use InvalidArgumentException;

/**
 * Browser authorization is allowed only to the HTTPS origin that a trusted
 * connector has already verified. Never derive verifiedOrigin from the URL
 * being validated or from an Admin form field.
 */
final class ExternalAuthorizationDestination
{
    public static function validate(string $url, ?string $verifiedOrigin): string
    {
        if ($url === '' || strlen($url) > 8192
            || preg_match('/[\x00-\x20\x7f]/', $url) === 1
            || filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new InvalidArgumentException('Invalid external authorization destination.');
        }

        $destination = parse_url($url);
        $origin = is_string($verifiedOrigin) ? parse_url($verifiedOrigin) : false;

        if (! is_array($destination) || ! is_array($origin)
            || strtolower((string) ($destination['scheme'] ?? '')) !== 'https'
            || strtolower((string) ($origin['scheme'] ?? '')) !== 'https'
            || isset($destination['user']) || isset($destination['pass']) || isset($destination['fragment'])
            || isset($origin['user']) || isset($origin['pass']) || isset($origin['query']) || isset($origin['fragment'])) {
            throw new InvalidArgumentException('Untrusted external authorization destination.');
        }

        $host = strtolower((string) ($destination['host'] ?? ''));
        $trustedHost = strtolower((string) ($origin['host'] ?? ''));

        if ($host === '' || $trustedHost === ''
            || (filter_var($host, FILTER_VALIDATE_IP) === false
                && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false)
            || ! hash_equals($trustedHost, $host)
            || ($destination['port'] ?? 443) !== ($origin['port'] ?? 443)) {
            throw new InvalidArgumentException('External authorization destination origin mismatch.');
        }

        return $url;
    }
}
