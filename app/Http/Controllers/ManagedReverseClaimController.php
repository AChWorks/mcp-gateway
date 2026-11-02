<?php

namespace App\Http\Controllers;

use App\Application\Targets\SshManagedReverseEnrollmentService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use RuntimeException;

final class ManagedReverseClaimController extends Controller
{
    public function __invoke(
        Request $request, string $enrollment,
        SshManagedReverseEnrollmentService $service,
    ): JsonResponse {
        // No web session/CSRF; this is deliberately limited to the one-use,
        // Target-bound enrollment token, with independent IP rate limiting.
        // Never log, flash, redirect, or return the supplied secret.
        $fields = $request->validate([
            'token' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]{64}$/D'],
            'public_key' => ['required', 'string', 'max:2048'],
        ]);
        try {
            $data = $service->claim($enrollment, $fields['token'], $fields['public_key']);
        } catch (InvalidArgumentException) {
            return response()->json([
                'error' => 'enrollment_rejected',
                'message' => 'Enrollment expired, already used or authorization rejected. Request Owner reconciliation.',
            ], 409)->header('Cache-Control', 'no-store');
        } catch (RuntimeException) {
            return response()->json([
                'error' => 'enrollment_unavailable',
                'message' => 'Gateway enrollment host policy is unavailable. Do not retry until an Owner reconciles the pending enrollment.',
            ], 503)->header('Cache-Control', 'no-store');
        }

        return response()->json([
            'state' => 'control_key_activated',
            'verified' => false,
            ...$data,
        ])->header('Cache-Control', 'no-store');
    }
}
