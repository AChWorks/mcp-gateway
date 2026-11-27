#!/usr/bin/env bash
# Exact released v3 installation -> candidate v3 browser-update acceptance.
# Disposable local DB only; never target any operator/production installation.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 <update-zip> <released-v3-install-zip>" >&2; exit 2; }
for tool in unzip php curl sha256sum mktemp grep sed awk; do
  command -v "$tool" >/dev/null || { echo "Missing test prerequisite: $tool" >&2; exit 2; }
done
fixture="$(realpath "$(dirname "$0")/../tests/Support/populated-migration-fixture.php")"
update_zip="$(realpath "$1")"
baseline_zip="$(realpath "$2")"
[[ -f "$update_zip" && -f "$baseline_zip" ]] || { echo "Missing update/baseline ZIP." >&2; exit 2; }
db_host="${UPDATE_TEST_DB_HOST:-127.0.0.1}"
db_name="${UPDATE_TEST_DB_DATABASE:-}"
db_user="${UPDATE_TEST_DB_USERNAME:-}"
db_pass="${UPDATE_TEST_DB_PASSWORD:-}"
db_port="${UPDATE_TEST_DB_PORT:-3306}"
[[ "$db_host" == '127.0.0.1' && "$db_name" =~ ^[a-z0-9_]+_test$ &&
    -n "$db_user" && -n "$db_pass" && "$db_port" =~ ^[0-9]+$ ]] || {
  echo "Only an explicitly configured disposable loopback *_test database is accepted." >&2
  exit 2
}
# Native database tooling must use the very same disposable server. In CI
# the pinned MariaDB service supplies the matching client and dump binaries.
db_native() {
  local tool="$1"
  shift
  if [[ -n "${UPDATE_TEST_DB_CONTAINER:-}" ]]; then
    [[ "$UPDATE_TEST_DB_CONTAINER" =~ ^[a-f0-9]{12,64}$ ]] || return 2
    MYSQL_PWD="$db_pass" docker exec -i -e MYSQL_PWD "$UPDATE_TEST_DB_CONTAINER" "$tool" \
      --protocol=tcp -h 127.0.0.1 -u "$db_user" "$@" "$db_name"
  else
    MYSQL_PWD="$db_pass" "$tool" --protocol=tcp -h "$db_host" -P "$db_port" -u "$db_user" "$@" "$db_name"
  fi
}
tmp="$(mktemp -d "${TMPDIR:-/tmp}/gateway-v3-browser-qa-XXXXXXXX")"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT

root="$(unzip -Z1 "$baseline_zip" | awk -F/ 'NF && $1 != "" && root == "" { root=$1 } END { print root }')"
[[ -n "$root" ]] || { echo "Cannot identify the released installation root." >&2; exit 1; }
unzip -q "$baseline_zip" -d "$tmp/installation"
site="$tmp/installation/$root"
[[ -f "$site/artisan" && -f "$site/vendor/autoload.php" ]] || { echo "Incomplete v3 baseline ZIP." >&2; exit 1; }
from="$(tr -d '[:space:]' < "$site/VERSION")"
[[ "$from" == 3.* ]] || { echo "Only installed v3 baselines are in scope." >&2; exit 1; }

mkdir -p "$site/storage/app/private"
app_key="$(php -r 'echo base64_encode(random_bytes(32));')"
cat > "$site/.env" <<EOF_ENV
APP_NAME="Gateway v3 Update QA"
APP_ENV=testing
APP_KEY=base64:$app_key
APP_DEBUG=false
APP_URL=https://gateway-update.example.test
DB_CONNECTION=mysql
DB_HOST=$db_host
DB_PORT=$db_port
DB_DATABASE=$db_name
DB_USERNAME=$db_user
DB_PASSWORD=$db_pass
SESSION_DRIVER=file
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=false
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
CACHE_STORE=file
QUEUE_CONNECTION=sync
FILESYSTEM_DISK=local
OAUTH_PRIVATE_KEY_PATH=storage/app/private/oauth/private.key
OAUTH_PUBLIC_KEY_PATH=storage/app/private/oauth/public.key
BRIDGE_CLIENT_PRIVATE_KEY_PATH=storage/app/private/bridge-client/private.key
BRIDGE_CLIENT_PUBLIC_KEY_PATH=storage/app/private/bridge-client/public.key
EOF_ENV
(
  cd "$site"
  php artisan gateway:oauth-keygen --force --no-interaction >/dev/null
  php artisan gateway:bridge-client-keygen --force --no-interaction >/dev/null
  php artisan migrate:fresh --force --no-interaction >/dev/null
  printf '{"installed":true}\n' > storage/app/private/installed
  printf 'PRIVATE-DO-NOT-LOSE\n' > storage/app/private/qa-update-sentinel.txt
  php -r '
    require "vendor/autoload.php";
    $app=require "bootstrap/app.php";
    $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    $owner=App\Models\User::query()->create([
      "name"=>"Gateway QA Owner","email"=>"gateway-qa-owner@example.test",
      "password"=>"CorrectHorse!234","role"=>"owner","access_enabled"=>true
    ]);
    App\Models\User::query()->create([
      "name"=>"Gateway QA Operator","email"=>"gateway-qa-operator@example.test",
      "password"=>"CorrectHorse!234","role"=>"operator","access_enabled"=>true,"target_scope_mode"=>"all"
    ]);
    App\Models\User::query()->create([
      "name"=>"Gateway QA Disabled","email"=>"gateway-qa-disabled@example.test",
      "password"=>"CorrectHorse!234","role"=>"owner","access_enabled"=>false
    ]);
    $t=App\Domain\Targets\Target::query()->create([
      "target_id"=>"qa330-ssh","display_name"=>"v3 preserved SSH Target",
      "connector_type"=>"ssh_direct"
    ]);
    $group=App\Domain\Targets\TargetGroup::query()->create(["name"=>"v3 preserved group"]);
    $group->targets()->attach($t->getKey());
    $group->users()->attach($owner->getKey());
    App\Domain\Targets\TargetCredential::query()->create([
      "target_record_id"=>$t->getKey(),"connector_type"=>"ssh_direct",
      "purpose"=>"qa-fixture","encrypted_payload"=>Illuminate\Support\Facades\Crypt::encryptString("qa-stable-secret"),
    ]);
    $db=Illuminate\Support\Facades\DB::class;
    $db::table("user_permission_denials")->insert([
      "user_id"=>$owner->getKey(),"permission"=>"ssh.file.write","created_at"=>now(),"updated_at"=>now()
    ]);
    $resource="https://mcp.example.test/mcp";
    $db::table("oauth_authorizations")->insert([
      "id"=>(string)Illuminate\Support\Str::ulid(),
      "user_id"=>$owner->getKey(),"client_id"=>"qa-client",
      "resource"=>$resource,"resource_hash"=>hash("sha256",$resource),
      "scopes"=>"[]","client_profile_key"=>"chatgpt",
      "client_profile_generation"=>1,"created_at"=>now(),"updated_at"=>now()
    ]);
  '
  php artisan gateway:check --no-interaction >/dev/null
)

# Seed real native credentials, exact and stale queued admissions, dispatched
# evidence, provider intents and transport generations using released code.
php "$fixture" "$site" seed "$tmp/populated.json"
php "$fixture" "$site" verify "$tmp/populated.json"
# Preserve a transaction-consistent database backup independently of the
# web updater's managed-file backup; verify recovery later from an empty DB.
( umask 077; db_native mariadb-dump --single-transaction --skip-lock-tables --no-tablespaces > "$tmp/baseline.sql" )
baseline_digest="$(php "$fixture" "$site" digest "$tmp/populated.json")"
test -s "$tmp/baseline.sql"
# Restore validation must boot the actual baseline, with the original key.
cp -a "$site" "$tmp/baseline"

# Snapshot real app data, encryption recovery, migration ledger and host-owned files.
cat > "$tmp/snapshot.php" <<'PHP'
<?php
chdir($argv[1]);
require 'vendor/autoload.php';
$app = require 'bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$db = Illuminate\Support\Facades\DB::class;
$target = App\Domain\Targets\Target::query()->where('target_id', 'qa330-ssh')->firstOrFail();
$group = App\Domain\Targets\TargetGroup::query()->where('name', 'v3 preserved group')->firstOrFail();
$cred = App\Domain\Targets\TargetCredential::query()->where('target_record_id', $target->getKey())->sole();
$owner = $db::table('users')->where('email', 'gateway-qa-owner@example.test')->first();
$operator = App\Models\User::query()->where('email', 'gateway-qa-operator@example.test')->firstOrFail();
$access = app(App\Application\Access\AccessControl::class);
$sshAllowed = $access->allowsTargetPermissions($operator, $target, App\Domain\Access\GatewayPermission::sshCapabilities());
$expectedMigrations = array_keys(app('migrator')->getMigrationFiles(database_path('migrations')));
$installedMigrations = $db::table('migrations')->orderBy('migration')->pluck('migration')->all();
if ($expectedMigrations === [] || $expectedMigrations !== $installedMigrations) {
    throw new RuntimeException('Installed migration identities do not match this runtime.');
}

if ($owner === null) { throw new RuntimeException('Owner was lost'); }
$data = [
 'owner' => [$owner->name, $owner->role, $owner->access_enabled],
 'operator' => [$operator->getRawOriginal('role'), $operator->getRawOriginal('target_scope_mode'), $sshAllowed],
 'target' => [$target->target_id, $target->connector_type, $target->display_name],
 'group' => [$group->name, $group->targets()->count(), $group->users()->count()],
 'credential' => Illuminate\Support\Facades\Crypt::decryptString($cred->encrypted_payload),
 'deny' => $db::table('user_permission_denials')->where('user_id', $owner->id)
   ->where('permission', 'ssh.file.write')->count(),
 'oauth_authorization' => $db::table('oauth_authorizations')->where('client_id', 'qa-client')
   ->where('user_id', $owner->id)->count(),
 'oauth_profile' => $db::table('oauth_client_profiles')->where('profile_key', 'chatgpt')->value('generation'),
];
if ($data['credential'] !== 'qa-stable-secret' || $data['deny'] !== 1 ||
    $data['oauth_authorization'] !== 1 || $data['group'][1] !== 1 ||
    $data['group'][2] !== 1 || $data['oauth_profile'] !== 1 ||
    in_array(true, $sshAllowed, true)) {
 throw new RuntimeException('Persistent fixture data or effective access is incorrect.');
}
echo hash('sha256', json_encode($data, JSON_THROW_ON_ERROR));
PHP
before_data="$(php "$tmp/snapshot.php" "$site")"
[[ -n "$before_data" ]] || exit 1
printf 'HOST-OWNED-USER-INI\n' > "$site/public/.user.ini"
mkdir -p "$site/bin"
printf 'OPERATOR-OWNED-CONTENT\n' > "$site/bin/qa-operator-script.sh"
(
 cd "$site"
 sha256sum .env public/.user.ini bin/qa-operator-script.sh    storage/app/private/qa-update-sentinel.txt    storage/app/private/oauth/private.key    storage/app/private/bridge-client/private.key > "$tmp/preserve.sha256"
)
old_artisan="$(sha256sum "$site/artisan" | awk '{print $1}')"
cp "$update_zip" "$site/$(basename "$update_zip")"
unzip -q "$update_zip" -d "$site"
to="$(tr -d '[:space:]' < "$site/update/UPDATE_VERSION")"
[[ "$to" == 3.* && "$to" != "$from" ]] || { echo "Invalid v3 update target." >&2; exit 1; }
[[ "$(tr -d '[:space:]' < "$site/VERSION")" == "$from" ]] || { echo "ZIP extraction replaced running code before approval." >&2; exit 1; }
[[ "$(sha256sum "$site/artisan" | awk '{print $1}')" == "$old_artisan" ]] || { echo "Extraction mutated live source." >&2; exit 1; }
( cd "$site" && sha256sum --check --strict "$tmp/preserve.sha256" >/dev/null )
[[ "$(php "$tmp/snapshot.php" "$site")" == "$before_data" ]] || { echo "Staging mutated persistent records." >&2; exit 1; }

# Exercise the real authenticated v3 browser entrypoint on the actual released
# installation, including Stage and Finish over HTTP, not direct CLI calls.
bash "$(dirname "$0")/test-v3-updater-http.sh" "$site" "$tmp" "$from" "$to"

[[ "$(tr -d '[:space:]' < "$site/VERSION")" == "$to" ]] || { echo "Update did not finish." >&2; exit 1; }
[[ ! -e "$site/storage/framework/down" ]] || { echo "Maintenance remained active." >&2; exit 1; }
[[ "$(php "$tmp/snapshot.php" "$site")" == "$before_data" ]] || { echo "Update altered existing authorization or credentials." >&2; exit 1; }
( cd "$site" && sha256sum --check --strict "$tmp/preserve.sha256" >/dev/null )
( cd "$site" && php artisan gateway:check --no-interaction >/dev/null )
php "$fixture" "$site" verify "$tmp/populated.json"
# Reconstruct the original schema from the backup, not by overlaying a dump
# onto the new tables. The explicit disposable-db guard above also governs
# the existing migrate:fresh. Never do this against an installed Gateway.
( cd "$site" && php artisan db:wipe --force --no-interaction >/dev/null )
db_native mariadb < "$tmp/baseline.sql"
[[ "$(php "$fixture" "$tmp/baseline" digest "$tmp/populated.json")" == "$baseline_digest" ]] || {
  echo "Restored database does not match the pre-upgrade records/schema." >&2; exit 1;
}
php "$fixture" "$tmp/baseline" verify "$tmp/populated.json"
[[ "$(php "$tmp/snapshot.php" "$tmp/baseline")" == "$before_data" ]] || { echo "Restored baseline identity mismatch." >&2; exit 1; }
# Reapply the candidate migrations to the restored released schema, proving
# recovery is usable and the translated authorities remain deterministic.
( cd "$site" && php artisan migrate --force --no-interaction >/dev/null )
php "$fixture" "$site" verify "$tmp/populated.json"
echo "PASS: native MariaDB backup restored to an empty schema, exact row digest and original native vaults verified, then migrated again."
[[ -d "$site/storage/app/private/update-backups" ]] || { echo "Code backup not retained." >&2; exit 1; }
printf 'PASS: verified released v%s -> v%s v3 browser updater stage+finish; persistent data, keys, grants, public host state, and health intact.\n' "$from" "$to"
