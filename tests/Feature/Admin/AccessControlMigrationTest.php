<?php

namespace Tests\Feature\Admin;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

#[Group('database-access')]
final class AccessControlMigrationTest extends TestCase
{
    use DatabaseMigrations;

    public function test_existing_local_users_keep_administrator_site_access_and_oldest_becomes_owner(): void
    {
        $migration = require database_path('migrations/2026_09_23_000000_add_access_control_foundation.php');
        $migration->down();

        $now = now();
        DB::table('users')->insert([
            [
                'name' => 'Existing First Admin',
                'email' => 'first-admin@example.test',
                'password' => 'legacy-hash',
                'created_at' => $now,
                'updated_at' => $now,
            ],
            [
                'name' => 'Existing Second Admin',
                'email' => 'second-admin@example.test',
                'password' => 'legacy-hash',
                'created_at' => $now,
                'updated_at' => $now,
            ],
        ]);

        $migration->up();

        $existing = DB::table('users')->orderBy('id')->get([
            'email',
            'role',
            'site_scope_mode',
            'access_enabled',
        ]);

        self::assertCount(2, $existing);
        self::assertSame('owner', $existing[0]->role);
        self::assertSame('all', $existing[0]->site_scope_mode);
        self::assertSame(1, (int) $existing[0]->access_enabled);
        self::assertSame('administrator', $existing[1]->role);
        self::assertSame('all', $existing[1]->site_scope_mode);
        self::assertSame(1, (int) $existing[1]->access_enabled);

        DB::table('users')->insert([
            'name' => 'Post Migration User',
            'email' => 'post-migration@example.test',
            'password' => 'new-hash',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $newUser = DB::table('users')
            ->where('email', 'post-migration@example.test')
            ->first(['role', 'site_scope_mode', 'access_enabled']);

        self::assertNotNull($newUser);
        self::assertSame('viewer', $newUser->role);
        self::assertSame('selected', $newUser->site_scope_mode);
        self::assertSame(1, (int) $newUser->access_enabled);
    }
}
