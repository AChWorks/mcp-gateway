<?php

namespace App\Application\Batch;

/** Explicitly audited, container-owned providers. No caller-chosen class. */
final readonly class TargetBatchProviderRegistry implements BatchProviderResolver
{
    public function __construct(
        private SshCommandBatchProvider $ssh,
        private WordpressBridgeInfoBatchProvider $wordpress,
    ) {}

    public function find(string $key): ?TargetBatchOperationProvider
    {
        return match ($key) {
            'ssh.command.run' => $this->ssh,
            'wordpress.bridge.info' => $this->wordpress,
            default => null,
        };
    }
}
