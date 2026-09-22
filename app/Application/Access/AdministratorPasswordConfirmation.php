<?php

namespace App\Application\Access;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

final class AdministratorPasswordConfirmation
{
    public function confirm(Request $request): User
    {
        $validated = $request->validate([
            'current_password' => ['required', 'string', 'max:255'],
        ]);

        $user = $request->user();
        abort_unless($user instanceof User, 401);

        if (! Hash::check(
            (string) $validated['current_password'],
            (string) $user->getRawOriginal('password'),
        )) {
            throw ValidationException::withMessages([
                'current_password' => __('The current password is invalid.'),
            ]);
        }

        return $user;
    }
}
