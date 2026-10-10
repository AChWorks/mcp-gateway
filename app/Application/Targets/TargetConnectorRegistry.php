<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\SshDirect\SshDirectTargetAdapter;
use App\Infrastructure\Connectors\WpAiBridge\WpAiBridgeTargetAdapter;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;

/**
 * One allowlisted dispatch point for implemented connector adapters.
 * Downstream operation names and ability catalogs are NOT connector types.
 */
final class TargetConnectorRegistry
{
    /** @var array<string, class-string<TargetConnectorAdapter>> */
    private const IMPLEMENTED = [
        'wp_ai_bridge' => WpAiBridgeTargetAdapter::class,
        'ssh_direct' => SshDirectTargetAdapter::class,
    ];

    /** @var array<string, TargetConnectorAdapter> */
    private array $resolved = [];

    public function __construct(private readonly Container $container) {}

    /** @return list<string> */
    public function types(): array
    {
        return array_keys(self::IMPLEMENTED);
    }

    public function forType(string $type): TargetConnectorAdapter
    {
        $class = self::IMPLEMENTED[$type]
            ?? throw new InvalidArgumentException('The connector type is not implemented.');

        return $this->resolved[$type] ??= $this->container->make($class);
    }

    public function forTarget(Target $target): TargetConnectorAdapter
    {
        return $this->forType($target->connector_type);
    }

    /**
     * Catch every built-in connector's pending state, including unexpected
     * cross-connector state left by a partial recovery. Do not delete it.
     */
    public function hasPendingDeletion(Target $target): bool
    {
        foreach ($this->types() as $type) {
            if ($this->forType($type)->hasPendingDeletion($target)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Inventory may show an unsupported historical connector but cannot run it.
     *
     * @return array<string, mixed>
     */
    public function publicMetadata(Target $target): array
    {
        if (! isset(self::IMPLEMENTED[$target->connector_type])) {
            return [];
        }

        return $this->forTarget($target)->publicMetadata($target);
    }
}
