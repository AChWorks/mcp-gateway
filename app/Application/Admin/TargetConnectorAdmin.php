<?php

namespace App\Application\Admin;

use App\Application\Targets\TargetConnectorRegistry;
use App\Domain\Targets\Target;
use App\Support\TargetRecoveryPresentation;
use Illuminate\Contracts\Container\Container;

/** UI companions do not register or make a connector executable. */
final class TargetConnectorAdmin
{
    /** @var array<string, class-string<TargetConnectorAdminPresenter>> */
    private const PRESENTERS = [
        'wp_ai_bridge' => WordpressTargetAdminPresenter::class,
        'ssh_direct' => SshTargetAdminPresenter::class,
    ];

    /** @var array<string, TargetConnectorAdminPresenter> */
    private array $resolved = [];

    public function __construct(
        private readonly TargetConnectorRegistry $connectors,
        private readonly Container $container,
    ) {}

    public function forType(string $type): ?TargetConnectorAdminPresenter
    {
        if (! in_array($type, $this->connectors->types(), true) || ! isset(self::PRESENTERS[$type])) {
            return null;
        }

        return $this->resolved[$type] ??= $this->container->make(self::PRESENTERS[$type]);
    }

    public function label(string $type): string
    {
        return $this->forType($type)?->definition()->label ?? __('Unsupported connector');
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
                'recovery' => TargetRecoveryPresentation::describe($target),
            ];
        }
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
