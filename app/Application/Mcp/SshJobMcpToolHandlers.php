<?php

namespace App\Application\Mcp;

use App\Application\Targets\SshJobCoordinator;
use App\Application\Targets\SshTargetConnectionException;
use App\Models\User;
use App\Support\OperationDiagnostics;
use Closure;
use Throwable;

/** Small client/Target-scoped MCP facade. Never audits script text or output. */
final readonly class SshJobMcpToolHandlers
{
    public function __construct(private SshJobCoordinator $jobs) {}

    /** @return array<string,mixed> */
    public function start(
        User $user, string $targetId, string $clientHash, string $requestId,
        string $script, int $maxRuntimeSeconds = 60,
    ): array {
        return $this->dispatch('ssh-job-start', fn () => $this->jobs->start(
            $user, $targetId, $clientHash, $requestId, $script, $maxRuntimeSeconds,
        ));
    }

    /** @return array<string,mixed> */
    public function status(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        return $this->dispatch('ssh-job-status', fn () => $this->jobs->status(
            $user, $targetId, $clientHash, $jobId,
        ));
    }

    /** @return array<string,mixed> */
    public function output(
        User $user, string $targetId, string $clientHash,
        string $jobId, string $stream = 'stdout', int $offset = 0, int $length = 16384,
    ): array {
        return $this->dispatch('ssh-job-output', fn () => $this->jobs->output(
            $user, $targetId, $clientHash, $jobId, $stream, $offset, $length,
        ));
    }

    /** @return array<string,mixed> */
    public function cancel(User $user, string $targetId, string $clientHash, string $jobId): array
    {
        return $this->dispatch('ssh-job-cancel', fn () => $this->jobs->cancel(
            $user, $targetId, $clientHash, $jobId,
        ));
    }

    /**
     * @param  Closure():array<string,mixed>  $operation
     * @return array<string,mixed>
     */
    private function dispatch(string $name, Closure $operation): array
    {
        try {
            $response = $operation();
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($name, $exception->reason);
        } catch (Throwable) {
            return $this->failed($name, 'job_unavailable');
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
                'message' => 'This SSH host lacks a supported persistent systemd manager. No detached job was launched.',
            ]];
        }

        return ['ok' => true, 'result' => $response];
    }

    /** @return array<string,mixed> */
    private function failed(string $operation, string $code): array
    {
        OperationDiagnostics::failure($operation, $code);

        return ['ok' => false, 'error' => [
            'code' => $code,
            'message' => $code === 'target_not_found'
                ? 'SSH Job or Target unavailable for this client.'
                : 'SSH Job operation could not be completed safely.',
            'next_step' => OperationDiagnostics::nextStep($code),
        ]];
    }
}
