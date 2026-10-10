<?php

namespace App\Application\Mcp;

use App\Application\Access\AccessControl;
use App\Application\Targets\SshFileRuntime;
use App\Application\Targets\SshTargetConnectionException;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Infrastructure\Activity\ActivityRecorder;
use App\Models\User;
use App\Support\CorrelationId;
use Closure;
use Throwable;

/** Target/operation-scoped SFTP tools. Never audit file data or full paths. */
final readonly class SshFileMcpToolHandlers
{
    public function __construct(
        private AccessControl $access,
        private ActivityRecorder $activity,
        private SshFileRuntime $runtime,
    ) {}

    /** @return array<string,mixed> */
    public function stat(User $user, string $target_id, string $path): array
    {
        return $this->dispatch($user, $target_id, 'ssh-file-stat', GatewayPermission::SshFileRead,
            fn (Target $target): array => $this->runtime->stat($user, $target, $path));
    }

    /** @return array<string,mixed> */
    public function list(User $user, string $target_id, string $path, int $limit = 100): array
    {
        return $this->dispatch($user, $target_id, 'ssh-file-list', GatewayPermission::SshFileRead,
            fn (Target $target): array => $this->runtime->list($user, $target, $path, $limit));
    }

    /** @return array<string,mixed> */
    public function read(
        User $user, string $target_id, string $path, int $offset = 0, int $length = 16384,
        ?int $expected_size = null, ?int $expected_mtime = null,
    ): array {
        return $this->dispatch($user, $target_id, 'ssh-file-read', GatewayPermission::SshFileRead,
            fn (Target $target): array => $this->runtime->read(
                $user, $target, $path, $offset, $length, $expected_size, $expected_mtime,
            ));
    }

    /** @return array<string,mixed> */
    public function write(
        User $user, string $target_id, string $path, string $content_base64,
        bool $overwrite = false, ?int $expected_size = null, ?int $expected_mtime = null,
    ): array {
        return $this->dispatch($user, $target_id, 'ssh-file-write', GatewayPermission::SshFileWrite,
            fn (Target $target): array => $this->runtime->write(
                $user, $target, $path, $content_base64, $overwrite, $expected_size, $expected_mtime,
            ));
    }

    /** @param Closure(Target):array<string,mixed> $action
     * @return array<string,mixed>
     */
    private function dispatch(
        User $user, string $targetId, string $tool, GatewayPermission $permission, Closure $action,
    ): array {
        if (strlen($targetId) > 64
            || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $targetId) !== 1) {
            return $this->failed($tool, null, 'target_not_found');
        }

        $target = $this->access->scopeTargets(Target::query(), $user, $permission)
            ->where('target_id', $targetId)
            ->where('connector_type', 'ssh_direct')
            ->first();
        if (! $target instanceof Target) {
            return $this->failed($tool, null, 'target_not_found');
        }

        try {
            $result = $action($target);
        } catch (SshTargetConnectionException $exception) {
            return $this->failed($tool, $target, $exception->reason);
        } catch (Throwable) {
            return $this->failed($tool, $target, 'file_unavailable');
        }

        $unknown = ($result['status'] ?? '') === 'outcome_unknown';
        $this->activity->record(
            CorrelationId::current(), $tool, $unknown ? 'unknown' : 'success',
            $target, $unknown ? 'outcome_unknown' : null,
        );

        return [
            'ok' => ! $unknown,
            'target_id' => $target->target_id,
            'result' => $result,
            ...($unknown ? ['error' => [
                'code' => 'outcome_unknown',
                'message' => 'Remote file mutation may have occurred; inspect before any manual retry.',
            ]] : []),
        ];
    }

    /** @return array<string,mixed> */
    private function failed(string $tool, ?Target $target, string $code): array
    {
        $this->activity->record(CorrelationId::current(), $tool, 'failure', $target, $code);

        return [
            'ok' => false,
            'error' => [
                'code' => $code,
                'message' => $code === 'target_not_found'
                    ? 'SSH Target is unavailable.'
                    : 'SSH file operation could not be completed safely.',
            ],
        ];
    }
}
