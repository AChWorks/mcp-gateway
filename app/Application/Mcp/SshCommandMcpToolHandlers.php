<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshStagedScriptExecution;
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
        return $this->execute($user, $target_id, $command, $timeout_seconds, null);
    }

    /** @return array<string,mixed> */
    public function runScript(User $user, string $target_id, string $script, string $interpreter, int $timeout_seconds = 10): array
    {
        return $this->execute($user, $target_id, $script, $timeout_seconds, $interpreter);
    }

    /** @return array<string,mixed> */
    private function execute(User $user, string $target_id, string $command, int $timeout_seconds, ?string $interpreter): array
    {
        $operation = $interpreter === null ? 'ssh-command-run' : 'ssh-script-run';
        if (strlen($target_id) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $target_id) !== 1) {
            return $this->failed($operation, null, 'target_not_found');
        }
        // Resolve exact authorized Target BEFORE reading any credential or dialing.
        // ScopeTargets applies role ceiling, default SSH deny, direct/group denials
        // and configured Target scope, without exposing forbidden identifiers.
        $target = $this->access->scopeTargets(Target::query(), $user, GatewayPermission::SshCommandRun)
            ->where('target_id', $target_id)
            ->where('connector_type', 'ssh_direct')
            ->first();
        if (! $target instanceof Target || ($interpreter !== null
            && ! $this->access->allows($user, GatewayPermission::SshFileWrite, $target))) {
            return $this->failed($operation, null, 'target_not_found');
        }
        if (TargetOperationGate::isPaused($target)) {
            return $this->failed($operation, $target, 'target_paused');
        }
        $limits = $this->settings->sshCommandLimits();
        if (trim($command) === '' || strlen($command) > $limits['max_bytes']
            || str_contains($command, "\0") || $timeout_seconds < 1
            || $timeout_seconds > $limits['max_seconds']
            || ($interpreter !== null && ! SshStagedScriptExecution::validInterpreter($interpreter))) {
            return $this->failed($operation, $target, 'invalid_input', $limits);
        }

        try {
            $result = $interpreter === null
                ? $this->runtime->run($user, $target, $command, $timeout_seconds)
                : $this->runtime->runScript($user, $target, $command, $interpreter, $timeout_seconds);
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($operation, $target, $exception->reason, observed: $exception->diagnostics);
        } catch (Throwable $exception) {
            return $this->failed($operation, $target, 'connection_unavailable', observed: [
                'failure_origin' => 'unknown',
                'failure_stage' => 'unknown',
                'provider_cause_unknown' => true,
                'exception_class' => $exception::class,
            ]);
        }

        $unknown = $result['status'] === 'outcome_unknown';
        $failed = $result['status'] === 'failed';
        $error = $unknown ? 'outcome_unknown' : ($failed ? (string) $result['error_code'] : null);
        $diagnostics = $result['__diagnostic_context'] ?? [];
        unset($result['__diagnostic_context'], $result['error_code']);
        $reference = CorrelationId::current();
        $cleanupUnconfirmed = ($result['temporary_cleanup_confirmed'] ?? true) === false;
        $this->activity->record(
            $reference, $operation, $unknown ? 'unknown' : ($failed ? 'failure' : 'success'),
            $target, $error,
            [
                ...($unknown ? [
                    'failure_origin' => 'unknown',
                    'failure_stage' => 'operation',
                    'effect_unconfirmed' => true,
                    'retry_safe' => false,
                ] : []),
                ...$diagnostics,
            ],
        );

        return [
            'ok' => $error === null,
            'target_id' => $target->target_id,
            'result' => $result,
            ...($error !== null ? ['error' => [
                'code' => $error,
                'message' => $unknown ? 'Remote command may have executed; do not retry automatically.'
                    : 'The staged script was not launched; inspect staging and cleanup evidence before another attempt.',
                'next_step' => OperationDiagnostics::nextStep($error),
                'diagnostic_reference' => $reference,
            ]] : ($cleanupUnconfirmed ? ['diagnostic_reference' => $reference] : [])),
        ];
    }

    /**
     * @param  array{max_bytes:int,max_seconds:int}|array{}  $limits
     * @param  array<string,mixed>  $observed
     * @return array<string,mixed>
     */
    private function failed(
        string $operation, ?Target $target, string $code, array $limits = [], array $observed = [],
    ): array {
        $reference = CorrelationId::current();
        $admission = in_array($code, ['rate_limited', 'connection_busy', 'admission_unavailable', 'timeout_unsupported', 'ssh_output_collector_unavailable'], true);
        $this->activity->record($reference, $operation, 'failure', $target, $code, [
            ...($admission ? [
                'failure_origin' => 'gateway_admission',
                'failure_stage' => 'admission',
                'request_not_sent' => true,
                'retry_safe' => true,
            ] : []),
            ...($code === 'egress_denied' && $observed === [] ? [
                'failure_origin' => 'gateway_admission',
                'failure_stage' => 'connection_setup',
                'request_not_sent' => true,
            ] : []),
            ...$observed,
        ]);

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
