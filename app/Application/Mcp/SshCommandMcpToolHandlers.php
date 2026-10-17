<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Application\Targets\TargetOperationGate;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Throwable;

/** Target-scoped, privilege-truthful MCP operation. Never logs command text. */
final readonly class SshCommandMcpToolHandlers
{
    public function __construct(
        private AccessControl $access,
        private ActivityRecorder $activity,
        private SshCommandRuntime $runtime,
        private OperationalSettings $settings,
    ) {}

    /** @return array<string,mixed> */
    public function run(User $user, string $target_id, string $command, int $timeout_seconds = 10): array
    {
        $operation = 'ssh-command-run';
        if (strlen($target_id) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $target_id) !== 1) {
            return $this->failed($operation, null, 'target_not_found');
        }
        // Resolve exact authorized Target BEFORE reading any credential or dialing.
        // ScopeTargets applies role ceiling, default SSH deny, direct/group denials
        // and explicit Selected scope, without exposing forbidden identifiers.
        $target = $this->access->scopeTargets(Target::query(), $user, GatewayPermission::SshCommandRun)
            ->where('target_id', $target_id)
            ->where('connector_type', 'ssh_direct')
            ->first();
        if (! $target instanceof Target) {
            return $this->failed($operation, null, 'target_not_found');
        }
        if (TargetOperationGate::isPaused($target)) {
            return $this->failed($operation, $target, 'target_paused');
        }
        $limits = $this->settings->sshCommandLimits();
        if (trim($command) === '' || strlen($command) > $limits['max_bytes']
            || str_contains($command, "\0") || $timeout_seconds < 1
            || $timeout_seconds > $limits['max_seconds']) {
            return $this->failed($operation, $target, 'invalid_input', $limits);
        }

        try {
            $result = $this->runtime->run($user, $target, $command, $timeout_seconds);
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($operation, $target, $exception->reason);
        } catch (Throwable) {
            return $this->failed($operation, $target, 'connection_unavailable');
        }

        $unknown = $result['status'] === 'outcome_unknown';
        $reference = CorrelationId::current();
        $this->activity->record(
            $reference, $operation, $unknown ? 'unknown' : 'success',
            $target, $unknown ? 'outcome_unknown' : null,
        );

        return [
            'ok' => ! $unknown,
            'target_id' => $target->target_id,
            'result' => $result,
            ...($unknown ? ['error' => [
                'code' => 'outcome_unknown',
                'message' => 'Remote command may have executed; do not retry automatically.',
                'next_step' => OperationDiagnostics::nextStep('outcome_unknown'),
                'diagnostic_reference' => $reference,
            ]] : []),
        ];
    }

    /**
     * @param  array{max_bytes:int,max_seconds:int}|array{}  $limits
     * @return array<string,mixed>
     */
    private function failed(string $operation, ?Target $target, string $code, array $limits = []): array
    {
        $reference = CorrelationId::current();
        $this->activity->record($reference, $operation, 'failure', $target, $code,
            $code === 'rate_limited' ? [
                'failure_origin' => 'gateway_admission',
                'failure_stage' => 'admission',
                'pre_dispatch' => true,
                'retry_safe' => true,
            ] : []);

        return [
            'ok' => false,
            'error' => [
                'code' => $code,
                'message' => $code === 'target_not_found'
                    ? 'SSH Target is unavailable.'
                    : 'SSH command could not be started safely.',
                'next_step' => OperationDiagnostics::nextStep($code),
                ...($limits !== [] ? ['effective_limits' => [
                    'max_command_bytes' => $limits['max_bytes'],
                    'max_timeout_seconds' => $limits['max_seconds'],
                ]] : []),
                ...($target instanceof Target && ! in_array($code, [
                    'target_not_found', 'invalid_input', 'target_paused',
                ], true) ? ['diagnostic_reference' => $reference] : []),
            ],
        ];
    }
}
