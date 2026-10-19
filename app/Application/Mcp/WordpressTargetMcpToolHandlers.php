<?php

namespace App\Application\Mcp;

use App\Application\Targets\WordpressTargetOperations;
use App\Models\User;

/**
 * MCP is only an authenticated presentation adapter. Shared operation
 * admission, Target authority, risk classification, dispatch and Activity
 * belong to the application service also used by Admin.
 */
final readonly class WordpressTargetMcpToolHandlers
{
    public function __construct(private WordpressTargetOperations $operations) {}

    /** @return array<string,mixed> */
    public function read(
        User $user,
        string $target_id,
        ?string $ability = null,
        int $page = 1,
        int $per_page = 10,
        ?string $namespace = null,
        ?string $search = null,
    ): array {
        return $this->operations->read($user, $target_id, $ability, $page, $per_page, $namespace, $search);
    }

    /** @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function execute(User $user, string $target_id, string $ability, array $input): array
    {
        return $this->operations->execute($user, $target_id, $ability, $input);
    }
}
