<?php

namespace App\Application\Admin;

use App\Domain\Access\GatewayRole;
use App\Models\User;
use Illuminate\Http\Request;

final readonly class AdminLoginDestination
{
    public function __construct(private AdminNavigation $navigation) {}

    public function afterAuthentication(Request $request, User $user): string
    {
        // Consume once just like redirect()->intended(), without retaining stale destinations.
        $intended = $this->sameOriginIntended($request->session()->pull('url.intended'), $request);
        $path = $intended === null ? null : parse_url($intended, PHP_URL_PATH);
        if ($path === '/update/') {
            return $user->access_enabled && $user->getAttribute('role') === GatewayRole::Owner
                ? $request->getSchemeAndHttpHost().'/update/'
                : $this->navigation->landingUrl($user);
        }
        if ($intended !== null
            && ! $this->navigation->isDeniedIndexPath($user, (string) parse_url($intended, PHP_URL_PATH))) {
            return $intended;
        }

        return $this->navigation->landingUrl($user);
    }

    private function sameOriginIntended(mixed $intended, Request $request): ?string
    {
        if (! is_string($intended) || $intended === '' || trim($intended) !== $intended
            || preg_match('/[\x00-\x1F\x7F]/', $intended) === 1) {
            return null;
        }

        // Backslashes or whitespace in the authority/path can be interpreted differently
        // by URL parsers. OAuth query bytes are deliberately not rewritten or decoded.
        $address = substr($intended, 0, strcspn($intended, '?#'));
        if (preg_match('/[\\\\\x00-\x20\x7F]/', $address) === 1) {
            return null;
        }
        $parts = parse_url($intended);
        if (! is_array($parts) || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }
        if (isset($parts['scheme']) || isset($parts['host'])) {
            if (strtolower($parts['scheme'] ?? '') !== $request->getScheme()
                || strcasecmp($parts['host'] ?? '', $request->getHost()) !== 0
                || ($parts['port'] ?? ($request->isSecure() ? 443 : 80)) !== $request->getPort()) {
                return null;
            }
        } elseif (! str_starts_with($intended, '/') || str_starts_with($intended, '//')) {
            return null;
        }

        $path = $parts['path'] ?? '';
        if ($path === '/update/') {
            return ! isset($parts['query']) && ! isset($parts['fragment']) ? $intended : null;
        }
        if ($path !== '/oauth/authorize'
            && ($path !== '/admin' && ! str_starts_with($path, '/admin/'))) {
            return null;
        }
        if (in_array(rtrim($path, '/'), ['/admin/login', '/admin/logout'], true)) {
            return null;
        }

        return $intended;
    }
}
