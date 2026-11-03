<?php

namespace App\Application\Targets;

use App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment;
use Carbon\CarbonImmutable;
use RuntimeException;

/** Content-addressed installer is verified before explicit sudo execution. */
final class SshManagedReverseInstallCommand
{
    public function scriptDigest(): string
    {
        $path = (string) config('ssh.managed_reverse.installer_path');
        $expected = (string) config('ssh.managed_reverse.installer_sha256');
        $actual = is_file($path) ? hash_file('sha256', $path) : false;
        if (preg_match('/^[a-f0-9]{64}$/D', $expected) !== 1
            || ! is_string($actual) || ! hash_equals($expected, $actual)) {
            throw new RuntimeException('The approved Target installer artifact is missing or has changed.');
        }

        return $expected;
    }

    public function command(SshManagedReverseEnrollment $enrollment, string $token): string
    {
        $gateway = rtrim((string) config('app.url'), '/');
        if (! preg_match('~^https://[a-zA-Z0-9.:-]+(?::[0-9]+)?$~D', $gateway)) {
            throw new RuntimeException('Use a configured HTTPS APP_URL before issuing a privileged install command.');
        }
        $sha = $this->scriptDigest();
        $target = $enrollment->target;
        $config = $target->sshConfig;
        if (! $config || $enrollment->state !== 'pending' || $enrollment->token_expires_at !== null && CarbonImmutable::parse($enrollment->token_expires_at)->isPast()) {
            throw new RuntimeException('Enrollment is unavailable or already used.');
        }

        $args = [
            '--gateway', $gateway,
            '--enrollment', (string) $enrollment->getKey(),
            '--token', $token,
            '--host-key-b64', base64_encode((string) $config->pinned_host_key),
            '--target-port', (string) $config->port,
            '--target-user', (string) $config->username,
        ];
        $quoted = implode(' ', array_map('escapeshellarg', $args));
        $url = escapeshellarg($gateway.'/reverse-ssh/installer/v1');
        $download = 'curl --proto \'=https\' --tlsv1.2 --fail --show-error --silent'
            .' --connect-timeout 8 --max-time 45 -o "$d/installer.sh" '.$url;
        $inner = 'set -eu; d="$(mktemp -d)"; trap \'rm -rf "$d"\' EXIT; '
            .$download.'; '
            .'printf \'%s  %s\\n\' '.escapeshellarg($sha).' "$d/installer.sh" | sha256sum -c -; '
            // Many servers are administered directly as root and do not ship
            // sudo. Keep the verified bytes/arguments identical in both paths.
            .'if [ "$(id -u)" -eq 0 ]; then bash "$d/installer.sh" '.$quoted
            .'; else command -v sudo >/dev/null 2>&1 || { echo "sudo is required for non-root installation" >&2; exit 1; }; '
            .'sudo bash "$d/installer.sh" '.$quoted.'; fi';

        // Shell history includes a short-lived enrollment token, never a
        // private key. Never show the token again after the one-time response.
        return 'sh -c '.escapeshellarg($inner);
    }
}
