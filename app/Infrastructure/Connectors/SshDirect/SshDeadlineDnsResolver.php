<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Application\Targets\SshTargetConnectionException;
use App\Infrastructure\Http\DeadlineDnsLookup;
use App\Infrastructure\Http\DnsLookupDeadlineExceeded;
use React\Dns\Resolver\ResolverInterface;

/**
 * Keep the SSH timeout/error contract while sharing the bounded A+AAAA DNS
 * engine with HTTPS. Host key and IP egress policies remain SSH-owned.
 */
final readonly class SshDeadlineDnsResolver
{
    public function __construct(private ?ResolverInterface $testResolver = null) {}

    /** @return list<string> */
    public function resolveBeforeDeadline(string $absoluteHost, int $deadlineNs): array
    {
        try {
            return (new DeadlineDnsLookup($this->testResolver))
                ->resolveBeforeDeadline($absoluteHost, $deadlineNs);
        } catch (DnsLookupDeadlineExceeded) {
            throw new SshTargetConnectionException('transfer_timed_out');
        } catch (\RuntimeException $exception) {
            throw new \RuntimeException('SSH DNS lookup unavailable.', 0, $exception);
        }
    }
}
