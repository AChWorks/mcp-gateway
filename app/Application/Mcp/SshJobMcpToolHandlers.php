<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Domain\Targets\TargetConnectionState;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use App\Support\OperationDiagnostics;
use Closure;
use Throwable;

/** Small client/Target-scoped MCP facade. Never audits script text or output. */
final readonly class SshJobMcpToolHandlers
{
    public function __construct(
        private SshJobCoordinator $jobs,
        private AccessControl $access,
        private ActivityRecorder $activity,
    ) {}

    /** @return array<string,mixed> */
    public function start(
        User $user, string $targetId, string $clientHash, string $requestId,
        string $script, int $maxRuntimeSeconds = 60,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-job-start', fn () => $this->jobs->start(
            $user, $targetId, $clientHash, $requestId, $script, $maxRuntimeSeconds,
        ));
    }

    /** @return array<string,mixed> */
    public function list(
        User $user, string $targetId, string $clientHash,
        ?string $status = null, ?string $cursor = null, int $limit = 20,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-jobs-list', fn () => $this->jobs->list(
            $user, $targetId, $clientHash, $status, $cursor, $limit,
        ));
    }

    /** @return array<string,mixed> */
    public function status(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        return $this->dispatch($user, $targetId, 'ssh-job-status', fn () => $this->jobs->status(
            $user, $targetId, $clientHash, $jobId,
        ));
    }

    /** @return array<string,mixed> */
    public function output(
        User $user, string $targetId, string $clientHash,
        string $jobId, string $stream = 'stdout', int $offset = 0, int $length = 16384,
    ): array {
        return $this->dispatch($user, $targetId, 'ssh-job-output', fn () => $this->jobs->output(
            $user, $targetId, $clientHash, $jobId, $stream, $offset, $length,
        ));
    }

    /** @return array<string,mixed> */
    public function cancel(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        return $this->dispatch($user, $targetId, 'ssh-job-cancel', fn () => $this->jobs->cancel(
            $user, $targetId, $clientHash, $jobId,
        ));
    }

    /**
     * @param  Closure():array<string,mixed>  $operation
     * @return array<string,mixed>
     */
    private function dispatch(User $user, string $targetId, string $name, Closure $operation): array
    {
        try {
            $response = $operation();
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($user, $targetId, $name, $exception->reason, $exception->diagnostics);
        } catch (Throwable $exception) {
            return $this->failed($user, $targetId, $name, 'job_unavailable', [
                'failure_origin' => 'unknown',
                'failure_stage' => 'unknown',
                'provider_cause_unknown' => true,
                'exception_class' => $exception::class,
            ]);
        }
        $status = $response['status'] ?? null;
        if ($status === 'launch_unknown') {
            return ['ok' => false, 'result' => $response, 'error' => [
                'code' => 'outcome_unknown',
                'message' => 'The launch may have happened. Poll this exact job ID; never repeat a new launch.',
                'next_step' => OperationDiagnostics::nextStep('outcome_unknown'),
            ]];
        }
        if ($status === 'unsupported') {
            return ['ok' => false, 'result' => $response, 'error' => [
                'code' => 'job_unsupported',
                'message' => 'A supported persistent systemd manager could not be verified on this SSH host. No detached job was launched.',
            ]];
        }

        return ['ok' => true, 'result' => $response];
    }

    /**
     * Canonical Activity record for actionable failures, only after the
     * caller's current Target permissions are rechecked. Routine invalid/
     * unknown-Job denials do not write an attacker-amplifiable audit record.
     * This adds no Target lookup or DB write on the successful Job hot path.
     *
     * @param  array<string,mixed>  $observed
     * @return array<string,mixed>
     */
    private function failed(
        User $user, string $targetId, string $operation, string $code, array $observed = [],
    ): array {
        $reference = null;
        if (! in_array($code, ['target_not_found', 'invalid_input', 'forbidden'], true)) {
            try {
                $target = $this->diagnosticTarget($user, $targetId, $operation);
                if ($target instanceof Target) {
                    $reference = CorrelationId::current();
                    $admission = in_array($code, ['rate_limited', 'connection_busy', 'admission_unavailable'], true);
                    $this->activity->record($reference, $operation, 'failure', $target, $code, [
                        ...($admission ? [
                            'failure_origin' => 'gateway_admission',
                            'failure_stage' => 'admission',
                            'request_not_sent' => true,
                            'retry_safe' => true,
                        ] : [
                            'failure_origin' => 'unknown',
                            'failure_stage' => 'operation',
                            'provider_cause_unknown' => true,
                        ]),
                        ...$observed,
                    ]);
                }
            } catch (Throwable) {
                // Diagnostics must never override an SSH Job failure's result.
                OperationDiagnostics::failure($operation, $code);
            }
        }

        return ['ok' => false, 'error' => [
            'code' => $code,
            'message' => $code === 'target_not_found'
                ? 'SSH Job or Target unavailable for this client.'
                : 'SSH Job operation could not be completed safely.',
            'next_step' => OperationDiagnostics::nextStep($code),
            ...($reference !== null ? ['diagnostic_reference' => $reference] : []),
        ]];
    }

    private function diagnosticTarget(User $user, string $targetId, string $operation): ?Target
    {
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            return null;
        }

        $target = $this->access->scopeTargets(Target::query(), $user, GatewayPermission::SshCommandRun)
            ->where('target_id', $targetId)
            ->where('connector_type', 'ssh_direct')
            ->where('connection_state', TargetConnectionState::Connected)
            ->first();
        if (! $target instanceof Target) {
            return null;
        }
        if (($operation === 'ssh-job-output' || $operation === 'ssh-job-start')
            && ! $this->access->allows($user, GatewayPermission::SshFileRead, $target)) {
            return null;
        }
        if ($operation === 'ssh-job-start'
            && ! $this->access->allows($user, GatewayPermission::SshFileWrite, $target)) {
            return null;
        }

        return $target;
    }
}
