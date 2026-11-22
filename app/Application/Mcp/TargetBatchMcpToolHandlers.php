<?php

namespace App\Application\Mcp;

use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchCoordinator;
use App\Models\User;
use Illuminate\Http\Request;
use InvalidArgumentException;
use RuntimeException;

/** The MCP adapter supplies only the middleware-proven authenticated origin. */
final readonly class TargetBatchMcpToolHandlers
{
    public function __construct(
        private TargetBatchCoordinator $batches,
        private DeferredBatchAuthority $authority,
    ) {}

    /** @param list<string> $targetIds
     * @return array<string,mixed>
     */
    public function previewSsh(
        Request $request, User $user, array $targetIds, string $command,
        int $timeoutSeconds = 10, string $mode = 'concurrent', bool $stopOnFailure = false, int $parallelism = 1,
    ): array {
        return $this->safe(fn (): array => $this->batches->preview(
            $user, $this->authority->captureMcp($user, $request), 'ssh.command.run',
            $targetIds, ['command' => $command, 'timeout_seconds' => $timeoutSeconds],
            $mode, $stopOnFailure, $parallelism,
        ));
    }

    /** @param list<string> $targetIds
     * @return array<string,mixed>
     */
    public function runSsh(
        Request $request, User $user, string $requestId, array $targetIds,
        string $command, string $previewToken, int $timeoutSeconds = 10,
        string $mode = 'concurrent', bool $stopOnFailure = false, int $parallelism = 1,
    ): array {
        return $this->safe(fn (): array => $this->batches->create(
            $user, $this->authority->captureMcp($user, $request), $requestId,
            'ssh.command.run', $targetIds,
            ['command' => $command, 'timeout_seconds' => $timeoutSeconds], $previewToken,
            $mode, $stopOnFailure, $parallelism,
        ));
    }

    /** @param list<string> $targetIds
     * @return array<string,mixed>
     */
    public function previewWordpress(
        Request $request, User $user, array $targetIds, string $mode = 'concurrent',
        bool $stopOnFailure = false, int $parallelism = 1,
    ): array {
        return $this->safe(fn (): array => $this->batches->preview(
            $user, $this->authority->captureMcp($user, $request), 'wordpress.bridge.info',
            $targetIds, [], $mode, $stopOnFailure, $parallelism,
        ));
    }

    /** @param list<string> $targetIds
     * @return array<string,mixed>
     */
    public function runWordpress(
        Request $request, User $user, string $requestId, array $targetIds, string $previewToken,
        string $mode = 'concurrent', bool $stopOnFailure = false, int $parallelism = 1,
    ): array {
        return $this->safe(fn (): array => $this->batches->create(
            $user, $this->authority->captureMcp($user, $request), $requestId,
            'wordpress.bridge.info', $targetIds, [], $previewToken,
            $mode, $stopOnFailure, $parallelism,
        ));
    }

    /** @return array<string,mixed> */
    public function status(Request $request, User $user, string $batchId, int $offset = 0, int $limit = 50): array
    {
        return $this->safe(fn (): array => $this->batches->status(
            $user, $this->authority->captureMcp($user, $request), $batchId, $offset, $limit,
        ));
    }

    /** @return array<string,mixed> */
    public function cancel(Request $request, User $user, string $batchId): array
    {
        return $this->safe(fn (): array => $this->batches->cancel(
            $user, $this->authority->captureMcp($user, $request), $batchId,
        ));
    }

    /** @return array<string,mixed> */
    public function list(Request $request, User $user, ?string $cursor = null, int $limit = 20): array
    {
        return $this->safe(fn (): array => $this->batches->list(
            $user, $this->authority->captureMcp($user, $request), $cursor, $limit,
        ));
    }

    /** @return array<string,mixed> */
    private function safe(callable $run): array
    {
        try {
            return $run();
        } catch (InvalidArgumentException|RuntimeException $exception) {
            return ['ok' => false, 'error' => [
                'code' => 'batch_not_admitted', 'message' => $exception->getMessage(),
            ]];
        }
    }
}
