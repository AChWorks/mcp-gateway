<?php

namespace App\Application\Targets;

use App\Domain\Targets\Target;
use App\Infrastructure\Connectors\ArvanCloud\ArvanApiTargetAdapter;
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
        'arvancloud' => ArvanApiTargetAdapter::class,
    ];

    /** @var array<string, TargetConnectorAdapter> */
    private array $resolved = [];

    public function __construct(private readonly Container $container) {}

    /** @return list<string> */
    public function types(): array
    {
        return array_keys(self::IMPLEMENTED);
    }

    public static function supports(string $type): bool
    {
        return isset(self::IMPLEMENTED[$type]);
    }

    public function availableForTarget(Target $target): ?TargetConnectorAdapter
    {
        return self::supports($target->connector_type)
            ? $this->forType($target->connector_type)
            : null;
    }

    public function forType(string $type): TargetConnectorAdapter
    {
        $class = self::IMPLEMENTED[$type]
            ?? throw new InvalidArgumentException('The connector type is not implemented.');

        return $this->resolved[$type] ??= $this->container->make($class);
    }

    public function forTarget(Target $target): TargetConnectorAdapter
    {
        return $this->availableForTarget($target)
            ?? throw new TargetConnectorFailure(__('This Target connector is not currently available.'));
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
     * Only connectors with actual public metadata contribute, for the same
     * already authorized bounded set in both inventory and single-Target context.
     *
     * @param  list<Target>  $targets
     * @return array<string,array<string,mixed>>
     */
    public function publicMetadata(array $targets): array
    {
        $groups = [];
        foreach ($targets as $target) {
            $groups[$target->connector_type][] = $target;
        }
        $metadata = [];
        foreach ($groups as $type => $items) {
            if (! self::supports($type)) {
                continue;
            }
            $adapter = $this->forType($type);
            if (! $adapter instanceof TargetPublicMetadataContributor) {
                continue;
            }
            $ids = array_fill_keys(array_map(static fn (Target $target): string => (string) $target->getKey(), $items), true);
            foreach ($adapter->publicMetadata($items) as $id => $details) {
                if (isset($ids[$id])) {
                    $metadata[$id] = $details;
                }
            }
        }

        return $metadata;
    }
}
