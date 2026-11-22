<?php

namespace App\Http\Controllers\Admin;

use App\Application\Batch\DeferredBatchAuthority;
use App\Application\Batch\TargetBatchCoordinator;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use InvalidArgumentException;
use RuntimeException;

/** Human/Web entrypoint: session + CSRF, never forwarded MCP bearer state. */
final class TargetBatchController extends Controller
{
    public function __construct(
        private readonly TargetBatchCoordinator $batches,
        private readonly DeferredBatchAuthority $authority,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $input = $request->validate([
            'cursor' => ['nullable', 'string', 'size:26'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ]);

        return $this->safe(fn (User $user, array $origin): array => $this->batches->list(
            $user, $origin, $input['cursor'] ?? null, (int) ($input['limit'] ?? 20),
        ), $request);
    }

    public function preview(Request $request): JsonResponse
    {
        $input = $this->planInput($request);

        return $this->safe(fn (User $user, array $origin): array => $this->batches->preview(
            $user, $origin, $input['capability'], $input['target_ids'],
            $input['arguments'] ?? [], $input['execution_mode'] ?? 'concurrent',
            (bool) ($input['stop_on_failure'] ?? false), (int) ($input['parallelism'] ?? 1),
        ), $request);
    }

    public function create(Request $request): JsonResponse
    {
        $input = $this->planInput($request, true);

        return $this->safe(fn (User $user, array $origin): array => $this->batches->create(
            $user, $origin, $input['request_id'], $input['capability'],
            $input['target_ids'], $input['arguments'] ?? [], $input['preview_token'],
            $input['execution_mode'] ?? 'concurrent', (bool) ($input['stop_on_failure'] ?? false),
            (int) ($input['parallelism'] ?? 1),
        ), $request);
    }

    public function show(Request $request, string $batch): JsonResponse
    {
        $input = $request->validate([
            'offset' => ['sometimes', 'integer', 'min:0'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ]);

        return $this->safe(fn (User $user, array $origin): array => $this->batches->status(
            $user, $origin, $batch, (int) ($input['offset'] ?? 0), (int) ($input['limit'] ?? 50),
        ), $request);
    }

    public function cancel(Request $request, string $batch): JsonResponse
    {
        return $this->safe(fn (User $user, array $origin): array => $this->batches->cancel(
            $user, $origin, $batch,
        ), $request);
    }

    /** @return array<string,mixed> */
    private function planInput(Request $request, bool $execute = false): array
    {
        return $request->validate([
            'capability' => ['required', Rule::in(['ssh.command.run', 'wordpress.bridge.info'])],
            'target_ids' => ['required', 'array', 'min:1'],
            'target_ids.*' => ['required', 'string', 'max:64'],
            // No generic arbitrary WordPress Ability is admitted into Batch.
            'arguments' => ['sometimes', 'array:command,timeout_seconds'],
            'arguments.command' => ['required_if:capability,ssh.command.run', 'string'],
            'arguments.timeout_seconds' => ['sometimes', 'integer', 'min:1'],
            'execution_mode' => ['sometimes', Rule::in(['concurrent', 'rolling'])],
            'parallelism' => ['sometimes', 'integer', 'min:1'],
            'stop_on_failure' => ['sometimes', 'boolean'],
            'request_id' => $execute ? ['required', 'uuid'] : ['prohibited'],
            'preview_token' => $execute ? ['required', 'string', 'max:80'] : ['prohibited'],
        ]);
    }

    /** @param callable(User,array<string,mixed>):array<string,mixed> $operation */
    private function safe(callable $operation, Request $request): JsonResponse
    {
        $user = $request->user();
        abort_unless($user instanceof User, 401);
        try {
            $origin = $this->authority->captureWeb($user, $request);

            return response()->json($operation($user, $origin));
        } catch (InvalidArgumentException|RuntimeException $exception) {
            return response()->json(['ok' => false, 'error' => [
                'code' => 'batch_not_admitted', 'message' => $exception->getMessage(),
            ]], 422);
        }
    }
}
