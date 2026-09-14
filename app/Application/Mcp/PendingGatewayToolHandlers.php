<?php

namespace App\Application\Mcp;

final class PendingGatewayToolHandlers
{
    /** @return array{status: string, sites: array<int, never>} */
    public function sitesList(): array
    {
        return [
            'status' => 'site_routing_not_configured',
            'sites' => [],
        ];
    }

    /** @return array{status: string, site_id: string} */
    public function siteContext(string $site_id): array
    {
        return [
            'status' => 'site_routing_not_configured',
            'site_id' => $site_id,
        ];
    }

    /** @return array{status: string, site_id: string, ability: string|null} */
    public function siteAbilitiesRead(string $site_id, ?string $ability = null): array
    {
        return [
            'status' => 'site_routing_not_configured',
            'site_id' => $site_id,
            'ability' => $ability,
        ];
    }

    /** @param array<string, mixed> $input
     * @return array{status: string, site_id: string, ability: string}
     */
    public function siteAbilityExecute(string $site_id, string $ability, array $input): array
    {
        return [
            'status' => 'site_routing_not_configured',
            'site_id' => $site_id,
            'ability' => $ability,
        ];
    }
}
