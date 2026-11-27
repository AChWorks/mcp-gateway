<?php

namespace App\Application\Admin;

use App\Application\Targets\TargetConnectorRegistry;
use App\Domain\Targets\Target;
use Illuminate\Contracts\Container\Container;

/** UI companions do not register or make a connector executable. */
final class TargetConnectorAdmin
{
    /** @var array<string, class-string<TargetConnectorAdminPresenter>> */
    private const PRESENTERS = [
        'wp_ai_bridge' => WordpressTargetAdminPresenter::class,
        'ssh_direct' => SshTargetAdminPresenter::class,
        'arvancloud' => ArvanTargetAdminPresenter::class,
    ];

    /** @var array<string, TargetConnectorAdminPresenter> */
    private array $resolved = [];

    public function __construct(
        private readonly TargetConnectorRegistry $connectors,
        private readonly Container $container,
        private readonly TargetHealthAdmin $health,
    ) {}

    public function forType(string $type): ?TargetConnectorAdminPresenter
    {
        if (! TargetConnectorRegistry::supports($type) || ! isset(self::PRESENTERS[$type])) {
            return null;
        }

        return $this->resolved[$type] ??= $this->container->make(self::PRESENTERS[$type]);
    }

    public function label(string $type): string
    {
        return $this->forType($type)?->definition()->label ?? __('Unsupported connector');
    }

    /**
     * @param  array<string,mixed>  $details
     * @return array<string,mixed>
     */
    public function recovery(Target $target, array $details = []): array
    {
        $presenter = $this->forType($target->connector_type);
        if ($presenter !== null) {
            return $presenter->recovery($target, $details);
        }

        return [
            'title' => __('Connector unavailable'),
            'description' => __('This stored connector is not implemented. Its authentication, reachability and recovery requirements have not been evaluated.'),
            'reachability' => __('No supported connector evidence is available.'),
            'authorization' => __('Not evaluated: the connector implementation is unavailable.'),
            'operation' => __('Connector operations are unavailable.'),
            'history' => $target->last_error_code === null ? null
                : __('Recorded diagnostic: :code', ['code' => $target->last_error_code]),
            'tone' => 'caution',
            'canFinish' => false, 'canCancel' => false, 'needsExternalProof' => false,
        ];
    }

    /** @return array<string, string> */
    public function options(): array
    {
        $options = [];
        foreach ($this->connectors->types() as $type) {
            $definition = $this->forType($type)?->definition();
            if ($definition?->enrollmentView !== null) {
                $options[$type] = $definition->label;
            }
        }

        return $options;
    }

    /**
     * @param  list<Target>  $targets  already authorized and paginated
     * @return array<string, array<string, mixed>>
     */
    public function inventory(array $targets): array
    {
        $groups = [];
        $presentation = [];
        foreach ($targets as $target) {
            $type = $target->connector_type;
            $groups[$type][] = $target;
            $presentation[$target->target_id] = [
                'definition' => $this->forType($type)?->definition(),
                'label' => $this->label($type),
                'recovery' => $this->recovery($target),
            ];
        }
        $health = $this->health->forTargets($targets);
        foreach ($presentation as $id => &$row) {
            $row['health'] = $health[$id];
        }
        unset($row);
        foreach ($groups as $type => $items) {
            $groupIds = array_fill_keys(array_map(static fn (Target $target): string => $target->target_id, $items), true);
            foreach ($this->forType($type)?->inventory($items) ?? [] as $id => $details) {
                // A presenter cannot introduce another Target into this page.
                if (isset($groupIds[$id])) {
                    $presentation[$id] = [...$presentation[$id], ...$details];
                }
            }
        }

        return $presentation;
    }
}
