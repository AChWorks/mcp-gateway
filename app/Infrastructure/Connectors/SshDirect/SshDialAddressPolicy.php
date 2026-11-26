<?php

namespace App\Infrastructure\Connectors\SshDirect;

interface SshDialAddressPolicy
{
    /** @return list<string> Empty means no address is approved. */
    public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array;
}
