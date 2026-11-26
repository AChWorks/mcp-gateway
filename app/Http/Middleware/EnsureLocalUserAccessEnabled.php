<?php

namespace App\Http\Middleware;

use App\Application\Access\VerifiedExecutionContext;
use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

final class EnsureLocalUserAccessEnabled
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof User || $user->access_enabled) {
            if ($user instanceof User) {
                $request->attributes->set(VerifiedExecutionContext::REQUEST_ATTRIBUTE, VerifiedExecutionContext::human($user));
            }

            return $next($request);
        }

        Auth::logout();

        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        if ($request->is('oauth/authorize')) {
            return $next($request);
        }

        return redirect()->route('login');
    }
}
