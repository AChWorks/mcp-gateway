<?php

namespace App\Application\Batch;

use App\Application\Operations\OperationalSettings;
use App\Application\Targets\SshCommandRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Models\User;
use Closure;
use Throwable;

/** First real Batch consumer: existing pinned, authorized SSH command path. */
final readonly class SshCommandBatchProvider implements TargetBatchOperationProvider
{
    public function __construct(
        private SshCommandRuntime $runtime,
        private OperationalSettings $settings,
    ) {}

    public function key(): string
    {
        return 'ssh.command.run';
    }

    public function connectorType(): string
    {
        return 'ssh_direct';
    }

    public function permission(): GatewayPermission
    {
        return GatewayPermission::SshCommandRun;
    }

    public function isEffectful(): bool
    {
        return true;
    }

    public function validArguments(array $arguments): bool
    {
        $limits = $this->settings->sshCommandLimits();
        $command = $arguments['command'] ?? null;
        $timeout = $arguments['timeout_seconds'] ?? 10;

        foreach (array_keys($arguments) as $key) {
            if (! in_array($key, ['command', 'timeout_seconds'], true)) {
                return false;
            }
        }

        return is_string($command) && trim($command) !== ''
            && strlen($command) <= $limits['max_bytes'] && ! str_contains($command, "\0")
            && is_int($timeout) && $timeout >= 1 && $timeout <= $limits['max_seconds'];
    }

    public function execute(User $user, Target $target, array $arguments, Closure $beforeRemoteEffect, bool $requiresAiAccess): array
    {
        try {
            $result = $this->runtime->run(
                $user, $target, $arguments['command'], $arguments['timeout_seconds'] ?? 10,
                beforeRemoteEffect: $beforeRemoteEffect,
            );
        } catch (SshTargetConnectionException $exception) {
            return ['ok' => false, 'status' => 'failed', 'error_code' => $exception->reason,
                'diagnostics' => [
                    ...$exception->diagnostics,
                    'source_error_code' => $exception->reason,
                    'gateway_error_message' => $exception->getMessage(),
                ]];
        } catch (Throwable $exception) {
            return ['ok' => false, 'status' => 'outcome_unknown', 'error_code' => 'ssh_execution_unexpected',
                'diagnostics' => ['exception_class' => $exception::class, 'effect_unconfirmed' => true]];
        }

        if (($result['status'] ?? null) === 'outcome_unknown') {
            return ['ok' => false, 'status' => 'outcome_unknown', 'error_code' => 'outcome_unknown',
                'result' => $result,
                'diagnostics' => ['failure_stage' => 'operation', 'effect_unconfirmed' => true]];
        }
        $exit = $result['exit_code'] ?? null;

        return [
            'ok' => $exit === 0,
            'status' => $exit === 0 ? 'completed' : 'failed',
            'error_code' => $exit === 0 ? null : 'remote_exit_nonzero',
            'result' => $result,
            'diagnostics' => $exit === 0 ? [] : [
                'failure_stage' => 'operation',
                'source_error_code' => 'remote_exit_nonzero',
                'remote_exit_code' => $exit,
            ],
        ];
    }
}
