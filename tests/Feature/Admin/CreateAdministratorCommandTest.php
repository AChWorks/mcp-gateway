<?php

namespace Tests\Feature\Admin;

use App\Domain\Access\GatewayRole;
use App\Domain\Access\SiteScopeMode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

final class CreateAdministratorCommandTest extends TestCase
{
    use RefreshDatabase;

    public function test_command_does_not_expose_a_password_option(): void
    {
        $command = Artisan::all()['gateway:admin:create'];

        $this->assertFalse($command->getDefinition()->hasOption('password'));
    }

    public function test_command_creates_an_administrator_with_normalized_email_and_hashed_password(): void
    {
        $password = 'CorrectHorse!234';

        $this->artisan('gateway:admin:create', [
            '--name' => 'Gateway Admin',
            '--email' => 'ADMIN@Example.Test',
        ])
            ->expectsQuestion('Password', $password)
            ->expectsQuestion('Confirm password', $password)
            ->expectsOutput('Owner administrator created.')
            ->assertExitCode(0);

        $user = User::query()->where('email', 'admin@example.test')->firstOrFail();

        $this->assertSame('Gateway Admin', $user->name);
        $this->assertNotSame($password, $user->getRawOriginal('password'));
        $this->assertTrue(Hash::check($password, (string) $user->getRawOriginal('password')));
        $this->assertSame(GatewayRole::Owner, $user->role);
        $this->assertSame(SiteScopeMode::All, $user->site_scope_mode);
        $this->assertTrue($user->access_enabled);
    }

    public function test_command_rejects_a_weak_password(): void
    {
        $this->artisan('gateway:admin:create', [
            '--name' => 'Gateway Admin',
            '--email' => 'admin@example.test',
        ])
            ->expectsQuestion('Password', 'too-weak')
            ->expectsQuestion('Confirm password', 'too-weak')
            ->assertExitCode(1);

        $this->assertDatabaseCount('users', 0);
    }

    public function test_command_rejects_a_mismatched_confirmation(): void
    {
        $this->artisan('gateway:admin:create', [
            '--name' => 'Gateway Admin',
            '--email' => 'admin@example.test',
        ])
            ->expectsQuestion('Password', 'CorrectHorse!234')
            ->expectsQuestion('Confirm password', 'DifferentHorse!234')
            ->assertExitCode(1);

        $this->assertDatabaseCount('users', 0);
    }
}
