<?php

namespace App\Http\Controllers\OAuth;

use App\Application\Targets\WpAiBridgeTargetConnectionException;
use App\Application\Targets\WpAiBridgeTargetConnectionService;
use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class TargetOAuthCallbackController extends Controller
{
    public function __invoke(Request $request, WpAiBridgeTargetConnectionService $connections): RedirectResponse
    {
        $state = $request->query('state');
        $code = $request->query('code');
        $issuer = $request->query('iss');
        $error = $request->query('error');

        try {
            $target = $connections->completeCallback(
                is_string($state) ? $state : '',
                is_string($code) ? $code : null,
                is_string($issuer) ? $issuer : null,
                is_string($error) ? $error : null,
            );

            return redirect()->route('admin.targets.show', ['target' => $target->target_id])
                ->with('status', __('WordPress Target authorization completed.'));
        } catch (WpAiBridgeTargetConnectionException) {
            // Never redirect on the basis of a forged/unverified callback Target ID.
            return redirect()->route('admin.targets.index')
                ->with('target_connection_failed', true);
        }
    }
}
