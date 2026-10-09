<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private const LEGACY_TABLES = [
        'site_check_operation_targets',
        'site_check_operations',
        'site_group_permission_denials',
        'site_group_sites',
        'site_group_users',
        'site_groups',
        'user_site_permission_denials',
        'user_site_access',
        'site_oauth_flows',
        'site_credentials',
        'site_revocation_intents',
        'site_target_reservations',
        'sites',
    ];

    private const PERMISSION_RENAMES = [
        'connection.view' => 'gateway.connection.view',
        'sites.view' => 'targets.view',
        'sites.create' => 'targets.create',
        'sites.update' => 'targets.update',
        'sites.remove' => 'targets.remove',
        'connections.connect' => 'targets.connect',
        'connections.reconnect' => 'targets.reconnect',
        'connections.disconnect' => 'targets.disconnect',
        'connections.test' => 'targets.test',
        'abilities.inspect' => 'wordpress.abilities.inspect',
        'abilities.execute.readonly' => 'wordpress.abilities.execute.readonly',
        'abilities.execute.mutating' => 'wordpress.abilities.execute.mutating',
        'abilities.execute.destructive' => 'wordpress.abilities.execute.destructive',
        'abilities.execute.unclassified' => 'wordpress.abilities.execute.unclassified',
    ];

    private const UNCHANGED_PERMISSIONS = [
        'dashboard.view',
        'activity.view',
        'users.view',
        'users.manage',
        'security.manage',
    ];

    private const AGENT_ADMIN = [
        'agent.environment.read',
        'agent.command.run',
        'agent.root_command.run',
        'agent.job.start',
        'agent.job.read',
        'agent.job.stop',
        'agent.file.read',
        'agent.file.write',
        'agent.browser.setup',
        'agent.browser.run',
    ];

    private const SSH_ADMIN_OPERATOR = [
        'ssh.command.run',
        'ssh.file.read',
        'ssh.file.write',
    ];

    public function up(): void
    {
        // Preflight is deliberately before any DDL. MySQL/MariaDB DDL implicitly commits.
        $hadTargetState = false;
        foreach (self::LEGACY_TABLES as $table) {
            if (! Schema::hasTable($table)) {
                throw new RuntimeException('Historical Target schema is incomplete; restore the database and investigate before upgrading.');
            }
            if (DB::table($table)->exists()) {
                $hadTargetState = true;
            }
        }
        if (! Schema::hasColumn('users', 'site_scope_mode') || ! Schema::hasColumn('activity_events', 'site_id')) {
            throw new RuntimeException('Historical Target schema does not match the supported upgrade baseline.');
        }
        $hadTargetState = $hadTargetState || DB::table('activity_events')->whereNotNull('site_id')->exists();

        if ($hadTargetState && (
            (string) config('target_transition.reset_acknowledged') !== 'RESET_TARGET_STATE'
            || (string) config('target_transition.database_backup_verified') !== 'RESTORABLE_DATABASE_BACKUP_VERIFIED'
        )) {
            throw new RuntimeException(
                'This major upgrade deletes registered Targets, downstream credentials, Target access/groups and Target activity. '
                .'A consistent, restorable database backup and the explicit Target reset confirmations are required before migration.',
            );
        }

        // Never discover an unsupported role after already dropping historical tables.
        $roles = DB::table('users')->distinct()->pluck('role');
        foreach ($roles as $role) {
            if (! in_array((string) $role, ['owner', 'administrator', 'operator', 'viewer'], true)) {
                throw new RuntimeException('Unrecognized Gateway role requires reconciliation before Target migration.');
            }
        }

        $denialSnapshot = DB::table('user_permission_denials')
            ->get(['user_id', 'permission']);
        $known = array_merge(
            array_keys(self::PERMISSION_RENAMES),
            array_values(self::PERMISSION_RENAMES),
            self::UNCHANGED_PERMISSIONS,
            self::AGENT_ADMIN,
            self::SSH_ADMIN_OPERATOR,
        );
        foreach ($denialSnapshot as $denial) {
            if (! in_array((string) $denial->permission, $known, true)) {
                throw new RuntimeException('Unknown global permission denial requires reconciliation before Target migration.');
            }
        }
        if (Schema::hasTable('targets') || Schema::hasTable('target_credentials')) {
            throw new RuntimeException('A partial Target migration is present; do not attempt destructive automatic recovery.');
        }

        // Explicitly delete legacy Target-scoped activity. Gateway-wide activity is preserved.
        DB::table('activity_events')->whereNotNull('site_id')->delete();

        // Ordered by foreign key ownership; do not drop users, OAuth, or retention tables.
        foreach (self::LEGACY_TABLES as $table) {
            Schema::drop($table);
        }

        Schema::table('users', static function (Blueprint $table): void {
            $table->renameColumn('site_scope_mode', 'target_scope_mode');
        });

        Schema::create('targets', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('target_id', 64)->unique();
            $table->string('display_name', 160);
            $table->string('connector_type', 64);
            $table->string('connection_state', 32)->default('disconnected');
            $table->string('last_error_code', 64)->nullable();
            $table->timestamp('last_tested_at', 6)->nullable();
            $table->timestamp('connected_at')->nullable();
            $table->timestamp('last_success_at', 6)->nullable();
            $table->timestamp('last_failure_at', 6)->nullable();
            $table->string('last_failure_code', 64)->nullable();
            $table->timestamps();
            $table->index(['connector_type', 'connection_state'], 'targets_type_state_idx');
            $table->index(['display_name', 'target_id'], 'targets_name_id_idx');
            $table->index(['connection_state', 'display_name', 'target_id'], 'targets_state_name_idx');
            $table->index(['connection_state', 'last_success_at'], 'targets_state_success_idx');
        });

        Schema::create('wp_ai_bridge_target_configs', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->unique()->constrained('targets')->cascadeOnDelete();
            $table->string('base_url', 1024);
            $table->char('base_url_hash', 64)->unique();
            $table->string('mcp_resource_url', 1024);
            $table->string('oauth_issuer_url', 1024);
            $table->string('oauth_authorization_url', 1024);
            $table->string('oauth_token_url', 1024);
            $table->string('oauth_revocation_url', 1024);
            $table->timestamps();
        });

        Schema::create('target_credentials', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->constrained('targets')->cascadeOnDelete();
            $table->string('connector_type', 64);
            $table->string('purpose', 96);
            $table->longText('encrypted_payload');
            $table->timestamps();
            $table->unique(['target_record_id', 'connector_type', 'purpose'], 'target_credential_purpose_unique');
        });

        Schema::create('wp_ai_bridge_credential_metadata', static function (Blueprint $table): void {
            $table->foreignUlid('credential_id')->primary()->constrained('target_credentials')->cascadeOnDelete();
            $table->string('client_id', 255);
            $table->string('resource_url', 1024);
            $table->char('binding_hash', 64);
            $table->timestamp('access_expires_at')->nullable();
            $table->index(['client_id', 'binding_hash'], 'wp_credential_client_binding_idx');
        });

        Schema::create('wp_ai_bridge_target_reservations', static function (Blueprint $table): void {
            $table->char('target_hash', 64)->primary();
            $table->string('target_url', 1024);
            $table->string('owner_target_id', 64)->index();
            $table->foreignUlid('target_record_id')->nullable()->unique()->constrained('targets')->cascadeOnDelete();
            $table->timestamps();
        });

        Schema::create('wp_ai_bridge_revocation_intents', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->unique()->constrained('targets')->cascadeOnDelete();
            $table->string('kind', 16)->index();
            $table->timestamps();
        });

        Schema::create('wp_ai_bridge_oauth_flows', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('target_record_id')->unique()->constrained('targets')->cascadeOnDelete();
            $table->char('state_hash', 64)->unique();
            $table->longText('encrypted_context');
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
            $table->index('expires_at');
        });

        Schema::create('user_target_access', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignUlid('target_record_id')->constrained('targets')->cascadeOnDelete();
            $table->boolean('allowed')->default(true);
            $table->timestamps();
            $table->unique(['user_id', 'target_record_id']);
            $table->index(['user_id', 'allowed']);
        });

        Schema::create('user_target_permission_denials', static function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignUlid('target_record_id')->constrained('targets')->cascadeOnDelete();
            $table->string('permission', 96);
            $table->timestamps();
            $table->unique(['user_id', 'target_record_id', 'permission'], 'target_access_denials_unique');
            $table->index(['user_id', 'permission'], 'target_user_permission_idx');
        });

        Schema::create('target_groups', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('name', 160)->unique();
            $table->timestamps();
        });

        Schema::create('target_group_targets', static function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('target_group_id')->constrained('target_groups')->cascadeOnDelete();
            $table->foreignUlid('target_record_id')->constrained('targets')->cascadeOnDelete();
            $table->timestamps();
            $table->unique(['target_group_id', 'target_record_id'], 'target_group_target_unique');
            $table->index(['target_record_id', 'target_group_id'], 'target_group_target_idx');
        });

        Schema::create('target_group_users', static function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('target_group_id')->constrained('target_groups')->cascadeOnDelete();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->timestamps();
            $table->unique(['target_group_id', 'user_id']);
            $table->index(['user_id', 'target_group_id']);
        });

        Schema::create('target_group_permission_denials', static function (Blueprint $table): void {
            $table->id();
            $table->foreignUlid('target_group_id')->constrained('target_groups')->cascadeOnDelete();
            $table->string('permission', 96);
            $table->timestamps();
            $table->unique(['target_group_id', 'permission'], 'target_group_denials_unique');
            $table->index(['permission', 'target_group_id']);
        });

        Schema::create('target_check_operations', static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignId('creator_user_id')->constrained('users')->cascadeOnDelete();
            $table->uuid('idempotency_key');
            $table->unsignedTinyInteger('active_slot')->nullable();
            $table->string('status', 32);
            $table->timestamp('started_at', 6)->nullable();
            $table->timestamp('completed_at', 6)->nullable();
            $table->timestamps(6);
            $table->unique(['creator_user_id', 'idempotency_key'], 'target_check_creator_idempotency_unique');
            $table->unique(['creator_user_id', 'active_slot'], 'target_check_creator_active_unique');
            $table->index(['completed_at', 'id'], 'target_check_completed_idx');
        });

        Schema::create('target_check_operation_targets', static function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUuid('operation_id')->constrained('target_check_operations')->cascadeOnDelete();
            $table->foreignUlid('target_record_id')->nullable()->constrained('targets')->nullOnDelete();
            $table->unsignedTinyInteger('position');
            $table->string('target_id_snapshot', 64);
            $table->string('display_name_snapshot', 160);
            $table->string('status', 32);
            $table->unsignedTinyInteger('attempts')->default(0);
            $table->uuid('attempt_token')->nullable();
            $table->string('error_code', 64)->nullable();
            $table->timestamp('started_at', 6)->nullable();
            $table->timestamp('finished_at', 6)->nullable();
            $table->timestamps(6);
            $table->unique(['operation_id', 'position'], 'target_check_position_unique');
            $table->unique(['operation_id', 'target_id_snapshot'], 'target_check_snapshot_unique');
            $table->index(['operation_id', 'status', 'position'], 'target_check_claim_idx');
        });

        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->dropIndex('activity_events_site_id_index');
        });
        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->renameColumn('site_id', 'target_id');
        });
        Schema::table('activity_events', static function (Blueprint $table): void {
            $table->ulid('target_record_id')->nullable()->index();
            $table->string('connector_type_snapshot', 64)->nullable();
            $table->index('target_id');
        });

        // No global-denial table-wide delete. Insert modern denies before removing old aliases
        // so even interrupted permission translation cannot silently widen current authority.
        $now = now();
        foreach ($denialSnapshot as $denial) {
            $legacy = (string) $denial->permission;
            $mapped = self::PERMISSION_RENAMES[$legacy] ?? $legacy;
            if ($mapped === $legacy) {
                continue;
            }
            DB::table('user_permission_denials')->insertOrIgnore([
                'user_id' => $denial->user_id,
                'permission' => $mapped,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        }
        foreach ($denialSnapshot as $denial) {
            if (array_key_exists((string) $denial->permission, self::PERMISSION_RENAMES)) {
                DB::table('user_permission_denials')
                    ->where('user_id', $denial->user_id)
                    ->where('permission', $denial->permission)
                    ->delete();
            }
        }

        foreach (DB::table('users')->get(['id', 'role']) as $user) {
            if ((string) $user->role === 'owner') {
                continue;
            }
            $newPermissions = match ((string) $user->role) {
                'administrator' => [...self::AGENT_ADMIN, ...self::SSH_ADMIN_OPERATOR],
                'operator' => ['agent.environment.read', 'agent.command.run', ...self::SSH_ADMIN_OPERATOR],
                'viewer' => ['agent.environment.read'],
                default => throw new RuntimeException('Unrecognized Gateway role requires reconciliation before migration.'),
            };
            foreach ($newPermissions as $permission) {
                DB::table('user_permission_denials')->insertOrIgnore([
                    'user_id' => $user->id,
                    'permission' => $permission,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            }
        }
    }

    public function down(): void
    {
        throw new RuntimeException(
            'Target schema reset is intentionally irreversible. Use the verified pre-upgrade database backup for recovery.',
        );
    }
};
