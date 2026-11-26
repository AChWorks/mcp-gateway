<?php

namespace App\Application\Targets;

use App\Application\Access\VerifiedExecutionContext;
use App\Domain\Targets\Target;
use Closure;

/** Original authority ceiling for one compound WordPress operation. */
final readonly class WordpressExecutionScope
{
    /** @param array<string,bool> $permissions
     * @param  Closure():bool  $binding
     */
    public function __construct(
        public VerifiedExecutionContext $context,
        public Target $target,
        public array $permissions,
        public Closure $binding,
    ) {}
}
