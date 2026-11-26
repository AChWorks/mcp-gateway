<?php

namespace App\Application\Access;

use App\Models\User;
use Closure;

/** Request-local, server-owned authority. Never contains the bearer itself. */
final readonly class VerifiedExecutionContext
{
    public const REQUEST_ATTRIBUTE = self::class;

    private function __construct(
        public int $actorId,
        public string $channel,
        public ?string $tokenId = null,
        public ?string $authorizationId = null,
        public ?string $clientId = null,
        public ?string $profileKey = null,
        public ?int $profileGeneration = null,
        public ?Closure $attemptGuard = null,
    ) {}

    public static function mcp(User $user, string $tokenId, string $authorizationId, string $clientId, string $profileKey, int $generation): self
    {
        return new self((int) $user->getKey(), 'mcp', $tokenId, $authorizationId, $clientId, $profileKey, $generation);
    }

    public static function human(User $user): self
    {
        return new self((int) $user->getKey(), 'web');
    }

    public static function unverified(User $user): self
    {
        return new self((int) $user->getKey(), 'unverified');
    }

    public static function local(User $user): self
    {
        return new self((int) $user->getKey(), 'local');
    }

    /** @param Closure():bool $attemptGuard Current durable consent/attempt/binding decision. */
    public static function deferred(User $user, Closure $attemptGuard): self
    {
        return new self((int) $user->getKey(), 'deferred', attemptGuard: $attemptGuard);
    }
}
