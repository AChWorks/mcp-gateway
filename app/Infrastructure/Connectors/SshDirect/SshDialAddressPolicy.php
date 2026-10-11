<?php

namespace App\Infrastructure\Connectors\SshDirect;

interface SshDialAddressPolicy
{
    /** @return non-empty-list<string> */
    public function approvedDialAddresses(SshRegisteredEndpoint $endpoint, ?int $deadlineNs = null): array;
}
