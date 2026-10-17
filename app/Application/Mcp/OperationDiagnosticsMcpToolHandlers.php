<?php

namespace App\Application\Mcp;

use App\Infrastructure\Activity\ActivityFeed;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Str;

/**
 * Permissioned model/client access to the SAME safe Activity diagnostics as Admin.
 * No raw log reader, remote connector call or privilege escalation.
 */
final readonly class OperationDiagnosticsMcpToolHandlers
{
    public function __construct(private ActivityFeed $activity) {}

    /** @return array<string,mixed> */
    public function read(User $user, ?string $diagnostic_reference = null, ?string $target_id = null, int $page = 1): array
    {
        // Require either an exact reference or an exact Target, never a
        // global unscoped recent-error sweep. Unauthorized/unknown lookups
        // use the same failure to avoid cross-Target enumeration.
        if (($diagnostic_reference === null && $target_id === null)
            || ($diagnostic_reference !== null && ! Str::isUuid($diagnostic_reference))
            || ($target_id !== null && (strlen($target_id) > 64
                || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $target_id) !== 1))
            || $page < 1 || $page > 50) {
            return $this->unavailable();
        }

        try {
            // ActivityFeed enforces current activity.view, Target scopes,
            // group/direct denials and visibility against current Target IDs.
            $feed = $this->activity->page($user, $page, 10, $target_id, null,
                $diagnostic_reference, $diagnostic_reference === null);
        } catch (AuthorizationException) {
            return $this->unavailable();
        }

        if ($feed['items'] === []) {
            return $this->unavailable();
        }

        $events = [];
        foreach ($feed['items'] as $item) {
            $error = $item['error_code'];
            $events[] = [
                'timestamp' => $item['created_at'],
                'diagnostic_reference' => $item['correlation_id'],
                'target_id' => $item['target_id'],
                'connector_type' => $item['connector_type_snapshot'],
                'operation' => $item['operation'],
                'outcome' => $item['outcome'],
                'error_code' => $error,
                'diagnostics' => $item['diagnostics'],
                'diagnostic_state' => $item['diagnostics'] === []
                    ? 'not_recorded_or_expired' : 'available',
                'summary' => $error === null ? null : OperationDiagnostics::summary($error),
                'next_step' => $error === null ? null : OperationDiagnostics::nextStep($error),
            ];
        }

        return [
            'ok' => true,
            'diagnostic_reference' => $diagnostic_reference,
            'target_id' => $target_id,
            'lookup_mode' => $diagnostic_reference !== null ? 'reference' : 'recent_target_errors',
            'events' => $events,
            'page' => $feed['page'],
            'has_more' => $feed['has_more'],
        ];
    }

    /** @return array<string,mixed> */
    private function unavailable(): array
    {
        return [
            'ok' => false,
            'error' => [
                'code' => 'diagnostic_unavailable',
                'message' => 'No authorized matching diagnostic evidence is available.',
                'next_step' => 'Verify the reference, effective Activity permission, Target scope and configured retention. Do not blindly retry remote mutations.',
            ],
        ];
    }
}
