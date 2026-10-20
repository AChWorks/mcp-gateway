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

    /**
     * @return array<string,mixed>
     */
    public function publishCreate(
        User $user,
        string $target_id,
        string $title,
        string $content,
        string $operation_id,
        string $client_id,
        string $profile_key,
        int $profile_generation,
    ): array {
        return $this->operations->publishCreate(
            $user, $target_id, $title, $content, $operation_id,
            $client_id, $profile_key, $profile_generation,
        );
    }

    /** @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public function execute(User $user, string $target_id, string $ability, array $input): array
    {
        return $this->operations->execute($user, $target_id, $ability, $input, requiresAiAccess: true);
    }
}
