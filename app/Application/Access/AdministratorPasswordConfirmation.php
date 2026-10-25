<?php

namespace App\Application\Access;

use App\Models\User;
use App\Support\CredentialAttemptLock;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

final class AdministratorPasswordConfirmation
{
    // One shared limit across every sensitive Admin endpoint for this account.
    private const FAILURE_LIMIT = 5;

    private const FAILURE_WINDOW_SECONDS = 900;

    public function __construct(private readonly CredentialAttemptLock $attemptLock) {}

    public function confirm(Request $request): User
    {
        $validated = $request->validate([
            'current_password' => ['required', 'string', 'max:255'],
        ]);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        $key = 'admin:password-confirmation:'.hash('sha256', (string) $user->getAuthIdentifier());

        return $this->attemptLock->run($key, static function () use ($validated, $user, $key): User {
            if (RateLimiter::tooManyAttempts($key, self::FAILURE_LIMIT)) {
                throw new HttpResponseException(
                    response('Too many password confirmation attempts. Retry later.', 429)
                        ->header('Retry-After', (string) max(1, RateLimiter::availableIn($key)))
                        ->header('Cache-Control', 'no-store'),
                );
            }

            if (! Hash::check(
                (string) $validated['current_password'],
                (string) $user->getRawOriginal('password'),
            )) {
                RateLimiter::hit($key, self::FAILURE_WINDOW_SECONDS);

                throw ValidationException::withMessages([
                    'current_password' => __('The current password is invalid.'),
                ]);
            }

            RateLimiter::clear($key);

            return $user;
        });
    }
}
