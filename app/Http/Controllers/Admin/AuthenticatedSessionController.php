<?php

namespace App\Http\Controllers\Admin;

use App\Models\User;
use App\Support\AdminLoginIdentity;
use App\Support\CredentialAttemptLock;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

final readonly class AuthenticatedSessionController
{
    // Failed attempts across changing source IPs must not bypass the login gate.
    private const IDENTITY_FAILURE_LIMIT = 10;

    private const IDENTITY_FAILURE_WINDOW_SECONDS = 900;

    public function store(Request $request, CredentialAttemptLock $attemptLock, AdminLoginIdentity $loginIdentity): RedirectResponse
    {
        if (is_string($request->input('email'))) {
            $request->merge(['email' => Str::lower(trim((string) $request->input('email')))]);
        }

        $credentials = $request->validate([
            'email' => ['required', 'string', 'email:rfc', 'max:254'],
            'password' => ['required', 'string', 'max:255'],
        ]);

        // The failure quota and lock must represent the same database email
        // equivalence class, whether or not that email belongs to a User.
        $failureKey = $loginIdentity->failureKey($credentials['email']);

        return $attemptLock->run($failureKey, function () use ($credentials, $request, $failureKey): RedirectResponse {
            if (RateLimiter::tooManyAttempts($failureKey, self::IDENTITY_FAILURE_LIMIT)) {
                throw $this->rateLimited(RateLimiter::availableIn($failureKey));
            }

            if (! Auth::attempt($credentials)) {
                RateLimiter::hit($failureKey, self::IDENTITY_FAILURE_WINDOW_SECONDS);

                throw $this->invalidCredentials();
            }

            $user = $request->user();
            if (! $user instanceof User || ! $user->access_enabled) {
                Auth::logout();
                RateLimiter::hit($failureKey, self::IDENTITY_FAILURE_WINDOW_SECONDS);

                throw $this->invalidCredentials();
            }

            $request->session()->regenerate();
            RateLimiter::clear($failureKey);

            return redirect()->intended(route('admin.dashboard'));
        });
    }

    public function destroy(Request $request): RedirectResponse
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }

    private function rateLimited(int $retryAfter): HttpResponseException
    {
        return new HttpResponseException(
            response('Too many login attempts. Retry later.', 429)
                ->header('Retry-After', (string) max(1, $retryAfter))
                ->header('Cache-Control', 'no-store'),
        );
    }

    private function invalidCredentials(): ValidationException
    {
        return ValidationException::withMessages([
            'email' => __('The provided credentials are invalid.'),
        ]);
    }
}
