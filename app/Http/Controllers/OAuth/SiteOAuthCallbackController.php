<?php

namespace App\Http\Controllers\OAuth;

use App\Application\Sites\SiteConnectionException;
use App\Application\Sites\SiteConnectionService;
use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class SiteOAuthCallbackController extends Controller
{
    public function __invoke(Request $request, SiteConnectionService $connections): RedirectResponse
    {
        $state = $request->query('state');
        $code = $request->query('code');
        $issuer = $request->query('iss');
        $error = $request->query('error');

        try {
            $site = $connections->completeCallback(
                is_string($state) ? $state : '',
                is_string($code) ? $code : null,
                is_string($issuer) ? $issuer : null,
                is_string($error) ? $error : null,
            );

            return redirect()->route('admin.dashboard')->with('site_connection_status', 'connected:'.$site->site_id);
        } catch (SiteConnectionException $exception) {
            return redirect()->route('admin.dashboard')->with('site_connection_status', 'failed:'.$exception->reason);
        }
    }
}
