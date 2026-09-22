<?php

namespace App\Console\Commands;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;

final class CreateAdministrator extends Command
{
    protected $signature = 'gateway:admin:create {--name=} {--email=}';

    protected $description = 'Create an MCP Gateway administrator with an interactively entered password.';

    public function handle(): int
    {
        $name = trim((string) ($this->option('name') ?: $this->ask('Name')));
        $email = Str::lower(trim((string) ($this->option('email') ?: $this->ask('Email'))));
        $password = (string) $this->secret('Password');
        $passwordConfirmation = (string) $this->secret('Confirm password');

        $validator = Validator::make([
            'name' => $name,
            'email' => $email,
            'password' => $password,
            'password_confirmation' => $passwordConfirmation,
        ], [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email:rfc', 'max:254', 'unique:users,email'],
            'password' => [
                'required',
                'string',
                'max:255',
                'confirmed',
                Password::min(12)->mixedCase()->numbers()->symbols(),
            ],
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $error) {
                $this->error($error);
            }

            return self::FAILURE;
        }

        $role = User::query()->exists()
            ? GatewayRole::Administrator
            : GatewayRole::Owner;

        User::query()->create([
            'name' => $name,
            'email' => $email,
            'password' => $password,
            'role' => $role->value,
            'site_scope_mode' => SiteScopeMode::All->value,
            'access_enabled' => true,
        ]);

        $this->info($role === GatewayRole::Owner
            ? 'Owner administrator created.'
            : 'Administrator created.');

        return self::SUCCESS;
    }
}
