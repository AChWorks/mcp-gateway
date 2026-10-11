<?php

namespace App\Infrastructure\Http;

use React\Dns\Config\Config;
use React\Dns\Model\Message;
use React\Dns\RecordNotFoundException;
use React\Dns\Resolver\Factory;
use React\Dns\Resolver\ResolverInterface;
use React\EventLoop\StreamSelectLoop;
use RuntimeException;
use Throwable;

use function React\Promise\all;

/**
 * Deadline-bounded DNS lookups without blocking libc's dns_get_record().
 *
 * Uses only the host's configured DNS servers (no public fallback), collects
 * BOTH A and AAAA answers, and cancels outstanding network queries on expiry.
 * The calling outbound policy validates the complete numeric result set.
 */
final readonly class DeadlineDnsLookup
{
    public function __construct(private ?ResolverInterface $testResolver = null) {}

    /** @return list<string> */
    public function resolveBeforeDeadline(string $absoluteHost, int $deadlineNs): array
    {
        $this->ensureTime($deadlineNs);
        if (! str_ends_with($absoluteHost, '.') || strlen($absoluteHost) < 3) {
            throw new RuntimeException('DNS name must be an absolute FQDN.');
        }
        // React's DNS wire codec expects the bare domain and sends an
        // absolute QNAME. Passing a terminal dot as a literal query label
        // causes SERVFAIL on normal DNS servers; no OS search list is used.
        $queryHost = substr($absoluteHost, 0, -1);

        // An isolated event loop per operation also works in short-lived PHP
        // FPM/LSAPI requests. No global loop, background process, or daemon.
        $loop = new StreamSelectLoop;
        $resolver = $this->testResolver;
        if ($resolver === null) {
            $config = Config::loadSystemConfigBlocking();
            if ($config->nameservers === []) {
                throw new RuntimeException('DNS server configuration unavailable.');
            }
            $this->ensureTime($deadlineNs);
            $resolver = (new Factory)->create($config, $loop);
        }

        $this->ensureTime($deadlineNs);
        $ignoreMissingType = static function (Throwable $error): array {
            if ($error instanceof RecordNotFoundException && $error->getCode() === 0) {
                // NOERROR/NODATA is normal for IPv4-only or IPv6-only hosts.
                return [];
            }

            throw $error;
        };
        $requests = [
            $resolver->resolveAll($queryHost, Message::TYPE_A)->then(null, $ignoreMissingType),
            $resolver->resolveAll($queryHost, Message::TYPE_AAAA)->then(null, $ignoreMissingType),
        ];
        $both = all($requests);
        $finished = false;
        $expired = false;
        $answers = [];
        $failure = null;
        $both->then(
            static function (array $groups) use (&$finished, &$answers, $loop): void {
                $answers = array_merge(...$groups);
                $finished = true;
                $loop->stop();
            },
            static function (Throwable $error) use (&$finished, &$failure, $loop): void {
                $failure = $error;
                $finished = true;
                $loop->stop();
            },
        );

        $remaining = ($deadlineNs - hrtime(true)) / 1_000_000_000;
        if ($remaining <= 0) {
            $both->cancel();
            throw new DnsLookupDeadlineExceeded('Outbound DNS deadline exceeded.');
        }
        $timer = $loop->addTimer($remaining, static function () use (&$expired, $both, $loop): void {
            $expired = true;
            $both->cancel();
            $loop->stop();
        });

        try {
            if (! $finished) {
                $loop->run();
            }
        } finally {
            $loop->cancelTimer($timer);
            if (! $finished || $failure !== null) {
                // all() may reject as soon as one query fails while the other
                // remains live. Cancel BOTH underlying queries on failure.
                foreach ($requests as $request) {
                    $request->cancel();
                }
            }
        }
        if ($expired) {
            throw new DnsLookupDeadlineExceeded('Outbound DNS deadline exceeded.');
        }
        $this->ensureTime($deadlineNs);
        if ($failure !== null) {
            throw new RuntimeException('DNS lookup unavailable.', 0, $failure);
        }

        /** @var list<string> $answers */
        return $answers;
    }

    private function ensureTime(int $deadlineNs): void
    {
        if (hrtime(true) >= $deadlineNs) {
            throw new DnsLookupDeadlineExceeded('Outbound DNS deadline exceeded.');
        }
    }
}
