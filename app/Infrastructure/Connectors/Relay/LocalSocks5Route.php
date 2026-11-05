<?php

namespace App\Infrastructure\Connectors\Relay;

use InvalidArgumentException;

/**
 * Application-internal, Target-bound selected relay transport endpoint.
 *
 * Must be instantiated only after an authorized persisted Relay/Target
 * binding has been checked. Not an arbitrary caller-supplied proxy URL.
 */
final readonly class LocalSocks5Route
{
    private function __construct(
        public string $relayId,
        public int $loopbackPort,
    ) {}

    public static function fromApprovedBinding(string $relayId, int $loopbackPort): self
    {
        if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $relayId) !== 1
            || $loopbackPort < 1024 || $loopbackPort > 65535) {
            throw new InvalidArgumentException('Invalid approved Relay binding.');
        }

        return new self($relayId, $loopbackPort);
    }

    public function httpProxyUri(): string
    {
        // CURLOPT_RESOLVE selects the numeric destination. SOCKS5h would
        // instead ask the remote hop to re-resolve the untrusted hostname.
        return 'socks5://127.0.0.1:'.$this->loopbackPort;
    }
}
