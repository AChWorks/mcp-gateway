<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Fresh, empty v3 schema. The self-contained SQL snapshots have only the
     * effective Target-era schema, never v2 Site tables or historical transforms.
     * Individual PDO statements require no mysql/sqlite command-line tools.
     */
    public function up(): void
    {
        // Laravel creates an empty migrations table before running up().
        // Refuse v2, a failed partial install or an unrelated DB BEFORE DDL.
        $driver = DB::getDriverName();
        $mysqlFamily = in_array($driver, ['mariadb', 'mysql'], true);
        $database = DB::connection()->getDatabaseName();
        foreach (Schema::getTables() as $table) {
            // MariaDB's metadata enumeration may include other databases on
            // the *same server*. They are NOT part of this installation.
            if ($mysqlFamily && ($table['schema'] ?? null) !== $database) {
                continue;
            }
            if (($table['name'] ?? null) !== 'migrations' || DB::table('migrations')->exists()) {
                throw new RuntimeException(
                    'Gateway v3 requires a new, empty database. No existing tables/data were changed. '
                    .'Keep the v2 code, database and keys independently restorable; do not migrate v2 in place.',
                );
            }
        }

        if (! $mysqlFamily && $driver !== 'sqlite') {
            throw new RuntimeException('Gateway v3 requires MariaDB/MySQL; SQLite is allowed for isolated tests only.');
        }

        $path = database_path('schema/'.($mysqlFamily ? 'v3-mysql.sql' : 'v3-sqlite.sql'));
        $sql = @file_get_contents($path);
        if (! is_string($sql) || trim($sql) === '') {
            throw new RuntimeException('The packaged Gateway v3 schema is missing: '.basename($path));
        }
        $parts = preg_split('/;\s*(?:\r?\n|$)/', trim($sql));
        if (! is_array($parts)) {
            throw new RuntimeException('Could not parse the Gateway v3 schema.');
        }
        $statements = array_values(array_filter(array_map('trim', $parts), static fn (string $s): bool => $s !== ''));
        if ($statements === []) {
            throw new RuntimeException('Gateway v3 schema has no DDL.');
        }
        foreach ($statements as $statement) {
            if (preg_match('/\ACREATE (?:TABLE|(?:UNIQUE )?INDEX)\b/i', $statement) !== 1) {
                throw new RuntimeException('Gateway v3 schema contains an unexpected SQL statement.');
            }
        }

        // Tables are lexically ordered. Foreign keys are enforced normally
        // after creation; the schema contains no pre-existing data to bypass.
        if ($mysqlFamily) {
            Schema::disableForeignKeyConstraints();
        }
        try {
            foreach ($statements as $statement) {
                DB::statement($statement);
            }
        } finally {
            if ($mysqlFamily) {
                Schema::enableForeignKeyConstraints();
            }
        }

        $now = now();
        DB::table('activity_retention_state')->insert(['id' => 1]);
        DB::table('chatgpt_file_admission_guard')->insert(['id' => 1]);
        DB::table('oauth_client_profiles')->insert([
            'profile_key' => 'chatgpt',
            'client_id' => (string) config('oauth.client.id'),
            'auth_strategy' => 'cimd_private_key_jwt',
            'generation' => 1,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        DB::table('operational_settings')->insert([
            'id' => 1, 'overrides' => '{}', 'version' => 0,
            'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table('ssh_job_maintenance_progress')->insert([
            ['operation' => 'prune', 'created_at' => $now, 'updated_at' => $now],
            ['operation' => 'reconcile', 'created_at' => $now, 'updated_at' => $now],
        ]);
        DB::table('wp_credential_maintenance_progress')->insert(['id' => 1]);
    }

    public function down(): void
    {
        // Dropping a production baseline cannot restore credentials, consent
        // or effects. Database restoration is the supported rollback path.
        throw new RuntimeException(
            'Do not roll back the Gateway v3 baseline in place. Restore a verified full database backup.',
        );
    }
};
