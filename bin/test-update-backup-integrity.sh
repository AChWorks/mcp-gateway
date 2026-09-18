#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash bin/test-update-backup-integrity.sh <update-zip> <old-deployment-zip>" >&2
  exit 2
fi

update_zip="$1"
old_zip="$2"

for command in unzip php find sha256sum mktemp cp rm awk; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required test command is unavailable: $command" >&2; exit 1; }
done
[[ -f "$update_zip" ]] || { echo "Missing update ZIP: $update_zip" >&2; exit 1; }
[[ -f "$old_zip" ]] || { echo "Missing old deployment ZIP: $old_zip" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

unzip -Z1 "$old_zip" > "$tmp/old-zip-list.txt"
old_root_name="$(awk -F/ 'NF && $1 != "" {print $1; exit}' "$tmp/old-zip-list.txt")"
[[ -n "$old_root_name" ]] || { echo "Could not identify old package root." >&2; exit 1; }
unzip -q "$old_zip" -d "$tmp/old"
base="$tmp/old/$old_root_name"
[[ -d "$base" ]] || { echo "Old package root is missing." >&2; exit 1; }

DB_HOST_VALUE="${UPDATE_TEST_DB_HOST:-127.0.0.1}"
DB_PORT_VALUE="${UPDATE_TEST_DB_PORT:-3306}"
DB_DATABASE_VALUE="${UPDATE_TEST_DB_DATABASE:-mcp_gateway_update_test}"
DB_USERNAME_VALUE="${UPDATE_TEST_DB_USERNAME:-mcp_gateway}"
DB_PASSWORD_VALUE="${UPDATE_TEST_DB_PASSWORD:-test-password}"

cat > "$base/.env" <<EOF_ENV
APP_NAME="MCP Gateway Backup Integrity Test"
APP_ENV=testing
APP_KEY=base64:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=
APP_DEBUG=false
APP_URL=https://gateway-update.example.test
DB_CONNECTION=mysql
DB_HOST=$DB_HOST_VALUE
DB_PORT=$DB_PORT_VALUE
DB_DATABASE=$DB_DATABASE_VALUE
DB_USERNAME=$DB_USERNAME_VALUE
DB_PASSWORD=$DB_PASSWORD_VALUE
SESSION_DRIVER=file
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=false
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
CACHE_STORE=file
QUEUE_CONNECTION=sync
FILESYSTEM_DISK=local
MCP_BOOTSTRAP_FIXTURE_ENABLED=false
MCP_BOOTSTRAP_FIXTURE_TOKEN=
OAUTH_PRIVATE_KEY_PATH=storage/app/private/oauth/private.key
OAUTH_PUBLIC_KEY_PATH=storage/app/private/oauth/public.key
BRIDGE_CLIENT_PRIVATE_KEY_PATH=storage/app/private/bridge-client/private.key
BRIDGE_CLIENT_PUBLIC_KEY_PATH=storage/app/private/bridge-client/public.key
EOF_ENV

(
  cd "$base"
  php artisan gateway:oauth-keygen --force --no-interaction >/dev/null
  php artisan gateway:bridge-client-keygen --force --no-interaction >/dev/null
  php artisan migrate:fresh --force --no-interaction >/dev/null
  printf '{"installed":true}\n' > storage/app/private/installed
  php artisan gateway:check --no-interaction >/dev/null
)

candidate="$tmp/candidate"
mkdir -p "$candidate"
unzip -q "$update_zip" -d "$candidate"
new_version="$(tr -d '[:space:]' < "$candidate/update/UPDATE_VERSION")"
[[ "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid candidate version." >&2; exit 1; }

migration_db_state() {
  local root="$1"
  (
    cd "$root"
    php -r '
      require "vendor/autoload.php";
      $app = require "bootstrap/app.php";
      $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      $rows = Illuminate\Support\Facades\DB::table("migrations")
          ->orderBy("migration")
          ->get(["migration", "batch"])
          ->map(static fn ($row): array => [
              "migration" => (string) $row->migration,
              "batch" => (int) $row->batch,
          ])
          ->all();
      echo hash("sha256", json_encode($rows, JSON_THROW_ON_ERROR));
    '
  )
}

run_case() {
  local mode="$1"
  local case_root="$tmp/case-$mode"
  cp -a "$base" "$case_root"

  local staged_zip="$case_root/mcp-gateway-update-v$new_version.zip"
  cp "$update_zip" "$staged_zip"
  sha256sum "$staged_zip" > "$staged_zip.sha256"
  unzip -q "$staged_zip" -d "$case_root"

  local migrations_before
  migrations_before="$(migration_db_state "$case_root")"

  php -r '
    [$base, $mode] = array_slice($argv, 1);
    chdir($base);
    require $base."/vendor/autoload.php";
    $app = require $base."/bootstrap/app.php";
    $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    require $base."/update/WebUpdater.php";

    $token = hash("sha256", "backup-integrity-".$mode);
    $updater = new McpGatewayUpdate\WebUpdater($base, $base."/update");
    $stage = $updater->stage($token);

    $backups = glob($base."/storage/app/private/update-backups/*", GLOB_ONLYDIR);
    if (!is_array($backups) || count($backups) !== 1) {
        fwrite(STDERR, "Expected exactly one updater backup after stage.\n");
        exit(1);
    }
    $backup = $backups[0];
    $backupArtisan = $backup."/files/artisan";
    if (!is_file($backupArtisan)) {
        fwrite(STDERR, "Backup artisan file is missing before corruption.\n");
        exit(1);
    }

    $candidateHash = hash_file("sha256", $base."/artisan");
    if (!is_string($candidateHash)) {
        fwrite(STDERR, "Could not hash installed candidate artisan file.\n");
        exit(1);
    }

    if ($mode === "remove") {
        if (!unlink($backupArtisan)) {
            fwrite(STDERR, "Could not remove backed-up managed file.\n");
            exit(1);
        }
    } elseif ($mode === "corrupt") {
        if (file_put_contents($backupArtisan, "\n# corrupted backup regression\n", FILE_APPEND) === false) {
            fwrite(STDERR, "Could not corrupt backed-up managed file.\n");
            exit(1);
        }
    } else {
        fwrite(STDERR, "Unknown backup regression mode.\n");
        exit(1);
    }

    try {
        $updater->finish($token, $stage["continuation"]);
        fwrite(STDERR, "Rejected backup unexpectedly crossed the migration boundary.\n");
        exit(1);
    } catch (Throwable $e) {
        if (!str_contains($e->getMessage(), "backup failed integrity validation")) {
            fwrite(STDERR, $e->getMessage()."\n");
            exit(2);
        }
    }

    if (trim((string) file_get_contents($base."/VERSION")) !== $stage["to"]) {
        fwrite(STDERR, "Rejected backup caused candidate VERSION to be restored or changed.\n");
        exit(1);
    }
    $afterHash = hash_file("sha256", $base."/artisan");
    if (!is_string($afterHash) || !hash_equals($candidateHash, $afterHash)) {
        fwrite(STDERR, "Rejected backup destructively changed the installed candidate runtime.\n");
        exit(1);
    }
    if (!is_dir($backup)) {
        fwrite(STDERR, "Rejected backup was not retained for manual recovery evidence.\n");
        exit(1);
    }

    $statePath = $base."/storage/app/private/update-state.json";
    $state = json_decode((string) file_get_contents($statePath), true, 512, JSON_THROW_ON_ERROR);
    if (($state["phase"] ?? null) !== "failed-before-migration-backup"
        || ($state["migration_started"] ?? null) !== false) {
        fwrite(STDERR, "Rejected backup did not persist the expected pre-migration failure state.\n");
        exit(1);
    }
  ' "$case_root" "$mode"

  local migrations_after
  migrations_after="$(migration_db_state "$case_root")"
  [[ "$migrations_after" == "$migrations_before" ]] || { echo "Database migration state changed for rejected $mode backup." >&2; exit 1; }
  [[ -e "$case_root/storage/framework/down" ]] || { echo "Application did not remain in maintenance mode for rejected $mode backup." >&2; exit 1; }
  [[ -e "$case_root/storage/app/private/update-state.json" ]] || { echo "Updater state was not retained for rejected $mode backup." >&2; exit 1; }

  rm -rf "$case_root"
}

run_case remove
run_case corrupt

printf 'backup integrity fail-safe verified: missing and corrupted managed recovery files are rejected before migration without destructive restore.\n'
