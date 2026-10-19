<?php

namespace App\Http\Controllers\Admin;

use App\Application\Access\AccessControl;
use App\Application\Targets\WordpressTargetOperations;
use App\Domain\Access\GatewayPermission;
use App\Domain\Targets\Target;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The first human-facing shared-operation consumer: one genuinely read-only
 * trusted WordPress capability, no user-supplied arbitrary Ability execution.
 */
final class WordpressBridgeInfoController extends Controller
{
    public function __invoke(
        Request $request,
        string $target,
        AccessControl $access,
        WordpressTargetOperations $operations,
    ): Response {
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        // Resolve by the authenticated principal's view scope BEFORE fetching
        // the record. An unknown Target and a disallowed Target both return
        // the same response; route model binding must not disclose existence.
        abort_unless(preg_match('/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/D', $target) === 1, 404);
        $resolved = $access->scopeTargets(
            Target::query(), $user, GatewayPermission::TargetsView,
        )->where('target_id', $target)->where('connector_type', 'wp_ai_bridge')->first();
        abort_unless($resolved instanceof Target
            && $access->allows($user, GatewayPermission::WordpressAbilitiesExecuteReadonly, $resolved), 404);

        // No extra remote authority: this is the same connector operation
        // as MCP, restricted to a trusted Readonly classification.
        $operation = $operations->execute(
            $user, $resolved->target_id, 'wp-ai-bridge/bridge-info', [], readonlyOnly: true,
        );
        $ok = $operation['ok'] === true;
        $error = $ok ? [] : ($operation['error'] ?? []);
        $json = $ok ? json_encode(
            $operation['result'] ?? null,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        ) : null;
        $json = is_string($json) ? $json : '';
        $truncated = strlen($json) > 32768;

        $status = $ok ? 200 : match ($error['code'] ?? '') {
            'forbidden' => 404,
            'target_not_found' => 404,
            'target_paused' => 409,
            default => 502,
        };

        return response()->view('admin.targets.wordpress-bridge-info', [
            'target' => $resolved,
            'success' => $ok,
            'error' => $error,
            'response' => mb_strcut($json, 0, 32768, 'UTF-8'),
            'truncated' => $truncated,
        ], $status);
    }
}
