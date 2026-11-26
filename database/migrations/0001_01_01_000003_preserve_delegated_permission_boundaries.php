<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        // Previously All-scope non-Owners could never exercise SSH rights,
        // even when a Deny row was missing. Preserve that effective policy
        // until an Owner explicitly removes the relevant Denies.
        DB::table('users')->where('target_scope_mode', 'all')
            ->whereIn('role', ['administrator', 'operator'])
            ->select('id')->chunkById(100, static function ($users): void {
                $rows = [];
                foreach ($users as $user) {
                    foreach (['ssh.command.run', 'ssh.file.read', 'ssh.file.write'] as $permission) {
                        $rows[] = ['user_id' => $user->id, 'permission' => $permission,
                            'created_at' => now(), 'updated_at' => now()];
                    }
                }
                DB::table('user_permission_denials')->insertOrIgnore($rows);
            });

        // Preserve explicit existing edit restrictions when introducing
        // independently controllable connection and pause permissions.
        foreach ([
            'user_permission_denials' => ['user_id'],
            'user_target_permission_denials' => ['user_id', 'target_record_id'],
            'target_group_permission_denials' => ['target_group_id'],
        ] as $table => $keys) {
            DB::table($table)->where('permission', 'targets.update')
                ->select(['id', ...$keys])->chunkById(100, static function ($denials) use ($table, $keys): void {
                    $rows = [];
                    foreach ($denials as $denial) {
                        $identity = [];
                        foreach ($keys as $key) {
                            $identity[$key] = $denial->{$key};
                        }
                        foreach (['targets.configure', 'targets.operations.manage'] as $permission) {
                            $rows[] = [...$identity, 'permission' => $permission,
                                'created_at' => now(), 'updated_at' => now()];
                        }
                    }
                    DB::table($table)->insertOrIgnore($rows);
                });
        }
    }

    public function down(): void
    {
        // Denial rows are durable Owner-editable access decisions after
        // migration. Never delete them or silently broaden access on rollback.
    }
};
