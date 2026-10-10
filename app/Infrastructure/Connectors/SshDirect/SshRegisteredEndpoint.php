<?php

namespace App\Infrastructure\Connectors\SshDirect;

use InvalidArgumentException;

/**
 * Canonical, operator-registered SSH endpoint identity, not a verified connection.
 *
 * DNS resolution, outbound TCP approval and pinned host-key validation belong
 * to the later transport boundary. This value object performs no network I/O
 * and must never be treated as proof of a connected or trusted remote host.
 */
final readonly class SshRegisteredEndpoint
{
    private function __construct(
        public string $host,
        public int $port,
        public string $username,
        private bool $literalIp,
    ) {}

    public static function fromInput(string $host, int $port, string $username): self
    {
        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException('SSH port must be between 1 and 65535.');
        }

        $username = trim($username, ' ');
        if ($username === '' || strlen($username) > 128
            || preg_match('/^[a-zA-Z0-9_][a-zA-Z0-9_.+-]{0,127}$/D', $username) !== 1) {
            throw new InvalidArgumentException('SSH username is invalid.');
        }

        $host = strtolower(trim($host, ' '));
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }

        if ($host === '' || strlen($host) > 253) {
            throw new InvalidArgumentException('SSH host is invalid.');
        }

        $ip = @inet_pton($host);
        if ($ip !== false) {
            $normalized = inet_ntop($ip);
            if ($normalized === false) {
                throw new InvalidArgumentException('SSH host is invalid.');
            }

            return new self($normalized, $port, $username, true);
        }

        // Refuse ambiguous numeric/dotted shorthand that some resolvers treat
        // as an IP literal even though inet_pton() does not accept it.
        if (preg_match('/^[0-9.]+$/D', $host) === 1) {
            throw new InvalidArgumentException('SSH host is not a canonical IP address.');
        }

        $host = rtrim($host, '.');
        $labels = explode('.', $host);
        if (count($labels) < 2 || strlen($host) > 253) {
            throw new InvalidArgumentException('SSH hostname must be a valid fully qualified name.');
        }

        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > 63
                || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/D', $label) !== 1) {
                throw new InvalidArgumentException('SSH hostname is invalid.');
            }
        }

        return new self($host, $port, $username, false);
    }

    /**
     * Configured literal address only; NOT the verified TCP peer address.
     * Hostnames return null until a separate connector-owned, pinned-host-key
     * connection records the actual selected and verified peer IP.
     */
    public function configuredIp(): ?string
    {
        return $this->literalIp ? $this->host : null;
    }

    public function destinationLabel(): string
    {
        $host = str_contains($this->host, ':') ? '['.$this->host.']' : $this->host;

        return $this->username.'@'.$host.':'.$this->port;
    }

    /**
     * Human-facing text only; callers must escape it when rendering in HTML.
     * target_id is a previously authorized, immutable Gateway-local identity,
     * never computed from the mutable SSH hostname or IP address.
     */
    public function targetLabel(string $displayName, string $targetId): string
    {
        $suffix = $this->literalIp ? '' : ' (IP not yet verified)';

        return $displayName.' — '.$this->destinationLabel().' — '.$targetId.$suffix;
    }
}
