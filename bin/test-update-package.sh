#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash bin/test-update-package.sh <update-zip> <old-deployment-zip>" >&2
  exit 2
fi

update_zip="$1"
old_zip="$2"

for command in unzip php curl find sha256sum mktemp cp rm grep awk sed; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required test command is unavailable: $command" >&2; exit 1; }
done
[[ -f "$update_zip" ]] || { echo "Missing update ZIP: $update_zip" >&2; exit 1; }
[[ -f "$old_zip" ]] || { echo "Missing old deployment ZIP: $old_zip" >&2; exit 1; }

tmp="$(mktemp -d)"
server_pid=""
needs_sudo_cleanup=0
protected_public_enforced=0
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ "$needs_sudo_cleanup" -eq 1 ]] && command -v sudo >/dev/null 2>&1; then
    sudo -n rm -rf "$tmp" >/dev/null 2>&1 || true
  else
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

protect_host_public_state() {
  local root="$1"
  mkdir -p "$root/public/css"
  printf 'aaPanel-host-managed-state\n' > "$root/public/.user.ini"
  printf 'host-managed-shared-directory-file\n' > "$root/public/css/host-managed.txt"
  chmod 0444 "$root/public/.user.ini"

  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n chown root:root "$root/public" "$root/public/.user.ini"
    sudo -n chmod 1777 "$root/public"
    sudo -n chmod 0444 "$root/public/.user.ini"
    needs_sudo_cleanup=1
    protected_public_enforced=1

    if rm -f "$root/public/.user.ini" 2>/dev/null; then
      echo "Protected host-managed public regression setup is invalid: .user.ini was deletable by the updater user." >&2
      exit 1
    fi
  elif [[ "${UPDATE_TEST_REQUIRE_PROTECTED_PUBLIC:-0}" == "1" ]]; then
    echo "Protected host-managed public regression requires passwordless sudo on this runner." >&2
    exit 1
  fi
}

unzip -Z1 "$old_zip" > "$tmp/old-zip-list.txt"
old_root_name="$(awk -F/ 'NF && $1 != "" {print $1; exit}' "$tmp/old-zip-list.txt")"
[[ -n "$old_root_name" ]] || { echo "Could not identify old package root." >&2; exit 1; }
unzip -q "$old_zip" -d "$tmp/old"
target="$tmp/old/$old_root_name"
[[ -d "$target" ]] || { echo "Old package root is missing." >&2; exit 1; }

DB_HOST_VALUE="${UPDATE_TEST_DB_HOST:-127.0.0.1}"
DB_PORT_VALUE="${UPDATE_TEST_DB_PORT:-3306}"
DB_DATABASE_VALUE="${UPDATE_TEST_DB_DATABASE:-mcp_gateway_update_test}"
DB_USERNAME_VALUE="${UPDATE_TEST_DB_USERNAME:-mcp_gateway}"
DB_PASSWORD_VALUE="${UPDATE_TEST_DB_PASSWORD-test-password}"
DB_SOCKET_VALUE="${UPDATE_TEST_DB_SOCKET:-}"
if [[ -n "$DB_SOCKET_VALUE" && ! "$DB_SOCKET_VALUE" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
  echo "Unsafe update-test DB_SOCKET path." >&2
  exit 2
fi

cat > "$target/.env" <<EOF_ENV
APP_NAME="MCP Gateway Update Test"
APP_ENV=testing
APP_KEY=base64:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=
APP_DEBUG=false
APP_URL=https://gateway-update.example.test
DB_CONNECTION=mysql
DB_HOST=$DB_HOST_VALUE
DB_PORT=$DB_PORT_VALUE
DB_SOCKET=$DB_SOCKET_VALUE
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
  cd "$target"
  php artisan gateway:oauth-keygen --force --no-interaction >/dev/null
  php artisan gateway:bridge-client-keygen --force --no-interaction >/dev/null
  php artisan migrate:fresh --force --no-interaction >/dev/null
  php -r '
    require "vendor/autoload.php";
    $app = require "bootstrap/app.php";
    $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    App\Models\User::query()->create([
      "name" => "Gateway Admin",
      "email" => "admin@example.test",
      "password" => "CorrectHorse!234",
    ]);
  '
  printf '{"installed":true}\n' > storage/app/private/installed
  printf 'persistent-private-state\n' > storage/app/private/update-preserve-sentinel.txt
  printf 'stale-managed-file\n' > app/obsolete-update-test.txt
  php artisan gateway:check --no-interaction >/dev/null
)

env_hash_before="$(sha256sum "$target/.env" | awk '{print $1}')"
private_hash_before="$(sha256sum "$target/storage/app/private/update-preserve-sentinel.txt" | awk '{print $1}')"
old_version="$(tr -d '[:space:]' < "$target/VERSION")"

# Released-v1.2.1 real-schema regression, not a synthetic post-transition
# schema: seed connection data that is intentionally discarded and unrelated
# identity/security data that must survive the breaking browser upgrade.
if [[ "$old_version" == "1.2.1" ]]; then
  (
    cd "$target"
    php -r '
      require "vendor/autoload.php";
      $app = require "bootstrap/app.php";
      $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      $db = Illuminate\Support\Facades\DB::class;
      $owner = App\Models\User::query()->where("email", "admin@example.test")->firstOrFail();
      // The baseline creates its first account *after* migrate:fresh.
      // V1 defaults new accounts to Viewer; explicitly seed the owner role
      // rather than incorrectly attributing the seed role to migration.
      $owner->forceFill(["role" => "owner", "site_scope_mode" => "all", "access_enabled" => true])->save();
      $operator = App\Models\User::query()->create([
        "name" => "Legacy operator", "email" => "operator@example.test",
        "password" => "CorrectHorse!234", "role" => "operator",
        "site_scope_mode" => "selected", "access_enabled" => true,
      ]);
      $site = (string) Illuminate\Support\Str::ulid();
      $base = "https://legacy-wordpress.example.test";
      $db::table("sites")->insert([
        "id" => $site, "site_id" => "legacy-wordpress",
        "display_name" => "Historical WordPress", "base_url" => $base,
        "base_url_hash" => hash("sha256", $base),
        "connector_type" => "wp_ai_bridge", "connection_state" => "connected",
        "mcp_resource_url" => $base."/wp-json/wp-ai-bridge/v1/mcp",
        "oauth_issuer_url" => $base,
        "oauth_authorization_url" => $base."/oauth/authorize",
        "oauth_token_url" => $base."/oauth/token",
        "oauth_revocation_url" => $base."/oauth/revoke",
      ]);
      $db::table("site_credentials")->insert([
        "id" => (string) Illuminate\Support\Str::ulid(),
        "site_record_id" => $site,
        "client_id" => "https://gateway-update.example.test/oauth/client.json",
        "resource_url" => $base."/wp-json/wp-ai-bridge/v1/mcp",
        "binding_hash" => hash("sha256", "test-binding"),
        "encrypted_payload" => Illuminate\Support\Facades\Crypt::encryptString("historical-fixture"),
      ]);
      $db::table("user_site_access")->insert([
        "user_id" => $operator->id, "site_record_id" => $site, "allowed" => true,
      ]);
      $group = (string) Illuminate\Support\Str::ulid();
      $db::table("site_groups")->insert(["id" => $group, "name" => "Retired WordPress group"]);
      $db::table("site_group_sites")->insert(["site_group_id" => $group, "site_record_id" => $site]);
      $db::table("site_group_users")->insert(["site_group_id" => $group, "user_id" => $operator->id]);
      $db::table("user_permission_denials")->insert([
        "user_id" => $operator->id, "permission" => "sites.view",
      ]);
      foreach (["legacy-wordpress", null] as $siteId) {
        $db::table("activity_events")->insert([
          "id" => (string) Illuminate\Support\Str::ulid(),
          "correlation_id" => (string) Illuminate\Support\Str::uuid(),
          "actor_type" => "system", "site_id" => $siteId,
          "operation" => $siteId === null ? "keep-global-event" : "discard-site-event",
          "outcome" => "success",
        ]);
      }
      $grant = (string) Illuminate\Support\Str::ulid();
      $client = "https://chatgpt.com/oauth/client.json";
      $resource = "https://gateway-update.example.test/mcp";
      $data = ["authorization_id" => $grant, "client_id" => $client,
        "user_id" => $owner->id, "resource" => $resource];
      $db::table("oauth_authorizations")->insert([
        "id" => $grant, "user_id" => $owner->id, "client_id" => $client,
        "resource" => $resource, "resource_hash" => hash("sha256", $resource),
        "scopes" => "[\"mcp:use\"]",
      ]);
      $db::table("oauth_access_tokens")->insert([
        ...$data, "id" => "browser-old-access",
        "scopes" => "[\"mcp:use\"]", "expires_at" => now()->addHour(),
      ]);
      $db::table("oauth_refresh_tokens")->insert([
        ...$data, "id" => "browser-old-refresh",
        "access_token_id" => "browser-old-access",
        "expires_at" => now()->addDay(),
      ]);
      if ($db::getSchemaBuilder()->hasTable("oauth_client_profiles")) {
        file_put_contents("storage/app/private/v121-client-profiles-present", "yes");
      }
    '
    php artisan gateway:check --no-interaction >/dev/null
  )
  echo "Seeded actual published v1.2.1 WordPress connection, Target scope/group, ChatGPT OAuth grant/access/refresh and unrelated identity/Activity."
fi

# The first post-Target maintenance update must preserve already-installed
# v2.0.0 identities, group ACLs and credentials; it is not a new Site reset.
if [[ "$old_version" == "2.0.0" ]]; then
  (
    cd "$target"
    php -r '
      require "vendor/autoload.php";
      $app = require "bootstrap/app.php";
      $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      $db = Illuminate\Support\Facades\DB::class;
      $owner = App\Models\User::query()->where("email", "admin@example.test")->firstOrFail();
      $owner->forceFill(["role" => "owner", "target_scope_mode" => "all", "access_enabled" => true])->save();
      $operator = App\Models\User::query()->create([
        "name" => "Existing v2 operator", "email" => "v200-operator@example.test",
        "password" => "CorrectHorse!234", "role" => "operator",
        "target_scope_mode" => "selected", "access_enabled" => true,
      ]);
      $existing = App\Domain\Targets\Target::query()->create([
        "target_id" => "v200-wordpress", "display_name" => "Existing WordPress",
        "connector_type" => "wp_ai_bridge", "connection_state" => "disconnected",
      ]);
      $group = App\Domain\Targets\TargetGroup::query()->create(["name" => "Existing v2 group"]);
      $credential = App\Domain\Targets\TargetCredential::query()->create([
        "target_record_id" => $existing->getKey(), "connector_type" => "wp_ai_bridge",
        "purpose" => "wordpress_oauth",
        "encrypted_payload" => Illuminate\Support\Facades\Crypt::encryptString("v200-test-credential"),
      ]);
      $now = now();
      $db::table("target_group_targets")->insert([
        "target_group_id" => $group->getKey(), "target_record_id" => $existing->getKey(),
        "created_at" => $now, "updated_at" => $now,
      ]);
      $db::table("target_group_users")->insert([
        "target_group_id" => $group->getKey(), "user_id" => $operator->getKey(),
        "created_at" => $now, "updated_at" => $now,
      ]);
      $db::table("user_target_access")->insert([
        "target_record_id" => $existing->getKey(), "user_id" => $operator->getKey(),
        "allowed" => true, "created_at" => $now, "updated_at" => $now,
      ]);
      $db::table("user_target_permission_denials")->insert([
        "target_record_id" => $existing->getKey(), "user_id" => $operator->getKey(),
        "permission" => "wordpress.abilities.execute.mutating",
        "created_at" => $now, "updated_at" => $now,
      ]);
      $db::table("target_group_permission_denials")->insert([
        "target_group_id" => $group->getKey(),
        "permission" => "wordpress.abilities.execute.destructive",
        "created_at" => $now, "updated_at" => $now,
      ]);
      $db::table("user_permission_denials")->insert([
        "user_id" => $operator->getKey(), "permission" => "ssh.command.run",
        "created_at" => $now, "updated_at" => $now,
      ]);
      $resource = "https://gateway-update.example.test/mcp";
      $db::table("oauth_authorizations")->insert([
        "id" => (string) Illuminate\Support\Str::ulid(),
        "user_id" => $owner->getKey(),
        "client_id" => (string) config("oauth.client.id"),
        "client_profile_key" => "chatgpt",
        "client_profile_generation" => 1,
        "resource" => $resource, "resource_hash" => hash("sha256", $resource),
        "scopes" => "[\"mcp:use\"]",
      ]);
      if (! $credential->exists) {
        throw new RuntimeException("Could not seed v2 credential persistence fixture.");
      }
    '
  )
  echo "Seeded published v2.0.0 Target, credential, Target Group, user rules, denials and ChatGPT authorization for patch-upgrade preservation."
fi

candidate="$tmp/candidate"
mkdir -p "$candidate"
unzip -q "$update_zip" -d "$candidate"
new_version="$(tr -d '[:space:]' < "$candidate/update/UPDATE_VERSION")"
[[ -f "$candidate/public/update/index.php" && -f "$candidate/update/WebUpdater.php" ]] || { echo "Browser updater files are missing after extraction." >&2; exit 1; }
[[ -f "$candidate/update/MANAGED_PUBLIC_PATHS" ]] || { echo "Gateway-owned public path manifest is missing after extraction." >&2; exit 1; }

# Regression for the production incident: an unknown public/.user.ini is made
# non-deletable by the updater user while Gateway-owned public files remain
# replaceable. A forced pre-migration verification failure must restore the old
# managed runtime without touching host-managed public state.
rollback_target="$tmp/rollback-target"
cp -a "$target" "$rollback_target"
protect_host_public_state "$rollback_target"
rollback_user_ini_hash="$(sha256sum "$rollback_target/public/.user.ini" | awk '{print $1}')"
rollback_host_file_hash="$(sha256sum "$rollback_target/public/css/host-managed.txt" | awk '{print $1}')"
rollback_artisan_hash="$(sha256sum "$rollback_target/artisan" | awk '{print $1}')"
rollback_migrations_before="$(cd "$rollback_target" && php artisan migrate:status --no-interaction | sha256sum | awk '{print $1}')"
rollback_zip="$rollback_target/mcp-gateway-update-v$new_version.zip"
cp "$update_zip" "$rollback_zip"
sha256sum "$rollback_zip" > "$rollback_zip.sha256"
unzip -q "$rollback_zip" -d "$rollback_target"

php -r '
  [$base] = array_slice($argv, 1);
  chdir($base);
  require $base."/vendor/autoload.php";
  $app = require $base."/bootstrap/app.php";
  $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
  require $base."/update/WebUpdater.php";
  $token = str_repeat("a", 64);
  $updater = new McpGatewayUpdate\WebUpdater($base, $base."/update");
  $reset = $updater->targetResetPreflight();
  $attest = $reset["required"] ? [
      "reset_acknowledged" => "RESET_TARGET_STATE",
      "database_backup_verified" => "RESTORABLE_DATABASE_BACKUP_VERIFIED",
      "confirmed_target_version" => $reset["to"],
      "package_sha256" => $reset["package_sha256"],
  ] : [];
  $stage = $updater->stage($token, $attest);
  file_put_contents($base."/artisan", "\n# force pre-migration restore regression\n", FILE_APPEND);
  try {
    $updater->finish($token, $stage["continuation"]);
    fwrite(STDERR, "Forced pre-migration failure unexpectedly completed.\n");
    exit(1);
  } catch (Throwable $e) {
    if (!str_contains($e->getMessage(), "restored automatically")) {
      fwrite(STDERR, $e->getMessage()."\n");
      exit(2);
    }
  }
' "$rollback_target"

[[ "$(tr -d '[:space:]' < "$rollback_target/VERSION")" == "$old_version" ]] || { echo "Pre-migration restore did not restore the previous VERSION." >&2; exit 1; }
[[ "$(sha256sum "$rollback_target/artisan" | awk '{print $1}')" == "$rollback_artisan_hash" ]] || { echo "Pre-migration restore did not restore managed application files." >&2; exit 1; }
[[ "$(sha256sum "$rollback_target/public/.user.ini" | awk '{print $1}')" == "$rollback_user_ini_hash" ]] || { echo "Pre-migration restore changed host-managed public/.user.ini." >&2; exit 1; }
[[ "$(sha256sum "$rollback_target/public/css/host-managed.txt" | awk '{print $1}')" == "$rollback_host_file_hash" ]] || { echo "Pre-migration restore changed an unknown file inside a shared public directory." >&2; exit 1; }
[[ "$(cd "$rollback_target" && php artisan migrate:status --no-interaction | sha256sum | awk '{print $1}')" == "$rollback_migrations_before" ]] || { echo "Database migration state changed during the forced pre-migration restore regression." >&2; exit 1; }
[[ ! -e "$rollback_target/storage/framework/down" ]] || { echo "Application remained in maintenance mode after successful pre-migration restore." >&2; exit 1; }
[[ ! -e "$rollback_target/storage/app/private/update-state.json" ]] || { echo "Updater state remained after successful pre-migration restore." >&2; exit 1; }

if [[ "$needs_sudo_cleanup" -eq 1 ]]; then
  sudo -n rm -rf "$rollback_target"
else
  rm -rf "$rollback_target"
fi

protect_host_public_state "$target"
user_ini_hash_before="$(sha256sum "$target/public/.user.ini" | awk '{print $1}')"
user_ini_meta_before="$(stat -c '%u:%g:%a' "$target/public/.user.ini")"
public_dir_meta_before="$(stat -c '%u:%g:%a' "$target/public")"
host_file_hash_before="$(sha256sum "$target/public/css/host-managed.txt" | awk '{print $1}')"

# The real operator staging step: upload the named ZIP into the existing
# application root and extract it there. This must add only temporary updater
# files and must not replace the live application before confirmation.
canonical_zip="$target/mcp-gateway-update-v$new_version.zip"
cp "$update_zip" "$canonical_zip"
sha256sum "$canonical_zip" > "$canonical_zip.sha256"
unzip -q "$canonical_zip" -d "$target"
[[ -d "$target/update" && -f "$target/public/update/index.php" ]] || { echo "In-place extraction did not stage the browser updater." >&2; exit 1; }
[[ "$(tr -d '[:space:]' < "$target/VERSION")" == "$old_version" ]] || { echo "Extracting the update ZIP changed the live version before confirmation." >&2; exit 1; }
[[ -f "$target/app/obsolete-update-test.txt" ]] || { echo "Extracting the update ZIP overwrote managed application files before confirmation." >&2; exit 1; }

inspect_package() {
  local base="$1"
  local package="$2"
  php -r '
    [$base, $package, $autoload] = array_slice($argv, 1);
    require $autoload;
    require $package."/WebUpdater.php";
    $updater = new McpGatewayUpdate\WebUpdater($base, $package);
    try {
      $updater->inspect();
      exit(0);
    } catch (Throwable $e) {
      fwrite(STDERR, $e->getMessage()."\n");
      exit(1);
    }
  ' "$base" "$package" "$target/vendor/autoload.php"
}

# Browser preflight must reject same-version and downgrade targets before mutation.
printf '%s\n' "$new_version" > "$target/VERSION"
if inspect_package "$target" "$target/update" >"$tmp/same.out" 2>&1; then
  echo "Same-version update unexpectedly passed preflight." >&2
  exit 1
fi
grep -F "target version must be newer" "$tmp/same.out" >/dev/null || { cat "$tmp/same.out" >&2; echo "Same-version rejection was not actionable." >&2; exit 1; }
printf '99.99.99\n' > "$target/VERSION"
if inspect_package "$target" "$target/update" >"$tmp/downgrade.out" 2>&1; then
  echo "Downgrade unexpectedly passed preflight." >&2
  exit 1
fi
grep -F "target version must be newer" "$tmp/downgrade.out" >/dev/null || { cat "$tmp/downgrade.out" >&2; echo "Downgrade rejection was not actionable." >&2; exit 1; }
printf '%s\n' "$old_version" > "$target/VERSION"

# Tampering and symlinked package content must fail before target mutation.
cp -a "$target/update" "$tmp/tampered-update"
printf 'tampered\n' >> "$tmp/tampered-update/payload/VERSION"
if inspect_package "$target" "$tmp/tampered-update" >"$tmp/tampered.out" 2>&1; then
  echo "Tampered update unexpectedly passed preflight." >&2
  exit 1
fi
grep -F "checksum validation failed" "$tmp/tampered.out" >/dev/null || { cat "$tmp/tampered.out" >&2; echo "Tampered-package rejection was not actionable." >&2; exit 1; }

cp -a "$target/update" "$tmp/symlink-update"
ln -s /etc/passwd "$tmp/symlink-update/payload/unsafe-link"
if inspect_package "$target" "$tmp/symlink-update" >"$tmp/symlink.out" 2>&1; then
  echo "Symlinked update unexpectedly passed preflight." >&2
  exit 1
fi
grep -F "symbolic link" "$tmp/symlink.out" >/dev/null || { cat "$tmp/symlink.out" >&2; echo "Symlink-package rejection was not actionable." >&2; exit 1; }

unsafe_target="$tmp/unsafe-target"
mkdir -p "$unsafe_target"
if inspect_package "$unsafe_target" "$target/update" >"$tmp/unsafe.out" 2>&1; then
  echo "Unsafe target unexpectedly passed preflight." >&2
  exit 1
fi
grep -F "does not look like an installed MCP Gateway deployment" "$tmp/unsafe.out" >/dev/null || { cat "$tmp/unsafe.out" >&2; echo "Unsafe-target rejection was not actionable." >&2; exit 1; }

# A conflict on an explicitly Gateway-owned public path must fail preflight with
# the exact path before maintenance mode or application mutation. Unknown public
# files such as .user.ini are intentionally not part of this check.
mv "$target/public/index.php" "$target/public/index.php.issue44-original"
mkdir "$target/public/index.php"
if inspect_package "$target" "$target/update" >"$tmp/public-conflict.out" 2>&1; then
  echo "Managed public path conflict unexpectedly passed preflight." >&2
  exit 1
fi
grep -F "conflicts with a directory: public/index.php" "$tmp/public-conflict.out" >/dev/null || { cat "$tmp/public-conflict.out" >&2; echo "Managed public path conflict was not path-specific." >&2; exit 1; }
rmdir "$target/public/index.php"
mv "$target/public/index.php.issue44-original" "$target/public/index.php"

cat > "$tmp/router.php" <<'PHP_ROUTER'
<?php
$public = $_SERVER['DOCUMENT_ROOT'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$candidate = rtrim($public, '/').$path;
if ($path !== '/' && (is_file($candidate) || is_dir($candidate))) {
    return false;
}
require $public.'/index.php';
PHP_ROUTER

port="${UPDATE_TEST_HTTP_PORT:-18080}"
php -S "127.0.0.1:$port" -t "$target/public" "$tmp/router.php" >"$tmp/server.log" 2>&1 &
server_pid=$!
base_url="http://127.0.0.1:$port"
for attempt in $(seq 1 40); do
  if curl -fsS "$base_url/up" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
  if [[ "$attempt" -eq 40 ]]; then
    cat "$tmp/server.log" >&2
    echo "Update test web server did not become ready." >&2
    exit 1
  fi
done

https_header='X-Forwarded-Proto: https'
jar="$tmp/admin.cookies"

guest_code="$(curl -sS -c "$jar" -b "$jar" -o "$tmp/guest-update.html" -D "$tmp/guest-update.headers" -w '%{http_code}' -H "$https_header" "$base_url/update/")"
[[ "$guest_code" == "302" ]] || { cat "$tmp/guest-update.headers" >&2; echo "Guest browser updater access was not redirected to admin login." >&2; exit 1; }
grep -i '^Location: .*/admin/login' "$tmp/guest-update.headers" >/dev/null || { echo "Guest updater redirect did not target admin login." >&2; exit 1; }
grep -i '^Set-Cookie:' "$tmp/guest-update.headers" >/dev/null || { echo "Guest updater redirect did not preserve the intended update session." >&2; exit 1; }

curl -fsS -c "$jar" -b "$jar" -H "$https_header" "$base_url/admin/login" > "$tmp/login.html"
login_csrf="$(grep -o 'name="_token" value="[^"]*"' "$tmp/login.html" | head -n 1 | sed 's/.*value="\([^"]*\)"/\1/')"
[[ -n "$login_csrf" ]] || { echo "Could not extract admin login CSRF token." >&2; exit 1; }

# Follow the normal login redirect. The preserved intended URL must return the
# operator directly to /update/ rather than requiring the URL to be opened a
# second time.
curl -fsS -L -D "$tmp/login-flow.headers" -c "$jar" -b "$jar" -H "$https_header" \
  --data-urlencode "_token=$login_csrf" \
  --data-urlencode 'email=admin@example.test' \
  --data-urlencode 'password=CorrectHorse!234' \
  "$base_url/admin/login" > "$tmp/update.html"
grep -F "Installed:</strong> $old_version" "$tmp/update.html" >/dev/null || { cat "$tmp/update.html" >&2; echo "Administrator login did not return directly to the browser updater." >&2; exit 1; }
grep -F "Target:</strong> $new_version" "$tmp/update.html" >/dev/null || { echo "Browser updater did not show the target version after login." >&2; exit 1; }

# Browser consent is a fresh operator action tied to the exact uploaded
# package, never simply .env flags or a generic update button.
reset_post=()
if [[ "$old_version" == "1.2.1" ]]; then
  grep -F 'Breaking v2.0 Target/OAuth reset' "$tmp/update.html" >/dev/null || { echo "Destructive preflight warning is absent." >&2; exit 1; }
  grep -F 'Gateway OAuth client grants (including ChatGPT tokens)' "$tmp/update.html" >/dev/null || { echo "OAuth reset affected-state summary is absent." >&2; exit 1; }
  grep -F 'independent database backup REQUIRED' "$tmp/update.html" >/dev/null || { echo "Independent DB backup warning is absent." >&2; exit 1; }
  package_hash="$(grep -o 'name="package_sha256" value="[a-f0-9]*"' "$tmp/update.html" | head -n 1 | sed 's/.*value="\([a-f0-9]*\)"/\1/')"
  [[ "$package_hash" =~ ^[a-f0-9]{64}$ ]] || { echo "Package binding is absent from the consent form." >&2; exit 1; }
  reset_post=(
    --data-urlencode 'reset_acknowledged=RESET_TARGET_STATE'
    --data-urlencode 'database_backup_verified=RESTORABLE_DATABASE_BACKUP_VERIFIED'
    --data-urlencode "confirmed_target_version=$new_version"
    --data-urlencode "package_sha256=$package_hash"
  )
fi

update_csrf="$(grep -o 'name="_token" value="[^"]*"' "$tmp/update.html" | head -n 1 | sed 's/.*value="\([^"]*\)"/\1/')"
update_cookie="$(grep -i '^Set-Cookie: mcp_gateway_update_session=' "$tmp/login-flow.headers" | tail -n 1 | sed -E 's/^[^=]+=([^;]+).*/\1/' | tr -d '\r')"
[[ -n "$update_csrf" && "$update_cookie" =~ ^[a-f0-9]{64}$ ]] || { echo "Browser updater session/CSRF material was not issued." >&2; exit 1; }

admin_cookie_header="$(awk '
  BEGIN { first=1 }
  /^#/ && $0 !~ /^#HttpOnly_/ { next }
  NF >= 7 && $6 != "mcp_gateway_update_session" {
    if (!first) printf "; ";
    printf "%s=%s", $6, $7;
    first=0;
  }
' "$jar")"
if [[ -n "$admin_cookie_header" ]]; then
  cookie_header="$admin_cookie_header; mcp_gateway_update_session=$update_cookie"
else
  cookie_header="mcp_gateway_update_session=$update_cookie"
fi

if [[ "$old_version" == "1.2.1" ]]; then
  # A legitimate authenticated user clicking Start without the fresh
  # confirmations must not enter maintenance or mutate managed files.
  denied_code="$(curl -sS -H "$https_header" -H "Cookie: $cookie_header" \
    --data-urlencode "_token=$update_csrf" --data-urlencode 'action=start' \
    -o "$tmp/reset-denied.html" -w '%{http_code}' "$base_url/update/")"
  [[ "$denied_code" == "500" ]] || { echo "Unacknowledged destructive upgrade unexpectedly accepted (HTTP $denied_code)." >&2; exit 1; }
  grep -F 'both explicit browser confirmations' "$tmp/reset-denied.html" >/dev/null || { echo "Missing consent did not return actionable error." >&2; exit 1; }
  [[ "$(tr -d '[:space:]' < "$target/VERSION")" == "$old_version" ]] || { echo "Denied consent modified runtime VERSION." >&2; exit 1; }
  [[ -f "$target/app/obsolete-update-test.txt" ]] || { echo "Denied consent removed managed files." >&2; exit 1; }
  [[ ! -f "$target/storage/app/private/update-state.json" ]] || { echo "Denied consent wrote updater mutation state." >&2; exit 1; }
  [[ ! -e "$target/storage/framework/down" ]] || { echo "Denied consent entered maintenance." >&2; exit 1; }

  stale_code="$(curl -sS -H "$https_header" -H "Cookie: $cookie_header" \
    --data-urlencode "_token=$update_csrf" --data-urlencode 'action=start' \
    --data-urlencode 'reset_acknowledged=RESET_TARGET_STATE' \
    --data-urlencode 'database_backup_verified=RESTORABLE_DATABASE_BACKUP_VERIFIED' \
    --data-urlencode "confirmed_target_version=$new_version" \
    --data-urlencode "package_sha256=$(printf '0%.0s' {1..64})" \
    -o "$tmp/reset-wrong-package.html" -w '%{http_code}' "$base_url/update/")"
  [[ "$stale_code" == "500" ]] || { echo "Incorrect update-package fingerprint bypassed the reset gate (HTTP $stale_code)." >&2; exit 1; }
  [[ "$(tr -d '[:space:]' < "$target/VERSION")" == "$old_version" && ! -f "$target/storage/app/private/update-state.json" ]] || { echo "Incorrect package acknowledgment mutated the installation." >&2; exit 1; }
fi

curl -fsS -H "$https_header" -H "Cookie: $cookie_header" \
  --data-urlencode "_token=$update_csrf" \
  --data-urlencode 'action=start' "${reset_post[@]}" \
  -D "$tmp/stage.headers" \
  "$base_url/update/" > "$tmp/stage.html"
continuation="$(grep -o 'name="continuation" value="[a-f0-9]*"' "$tmp/stage.html" | head -n 1 | sed 's/.*value="\([a-f0-9]*\)"/\1/')"
[[ "$continuation" =~ ^[a-f0-9]{64}$ ]] || { cat "$tmp/stage.html" >&2; echo "Browser updater did not return a valid continuation token." >&2; exit 1; }
# A previously valid but nearly expired preflight cookie must be renewed at
# accepted Start, with its final expiry based on the end of a potentially long stage.
php -r '
  $lines = file($argv[1]);
  $cookies = array_values(array_filter($lines, static fn ($line) =>
    stripos($line, "Set-Cookie: mcp_gateway_update_session=") === 0));
  if ($cookies === []) { fwrite(STDERR, "Start did not renew updater cookie.\n"); exit(1); }
  $last = end($cookies);
  if (!preg_match("/expires=([^;]+)/i", $last, $m)) { exit(2); }
  $remaining = strtotime($m[1]) - time();
  if ($remaining < 1740 || $remaining > 1805) {
    fwrite(STDERR, "Updater cookie TTL was not fresh after stage: ".$remaining." sec.\n"); exit(3);
  }
' "$tmp/stage.headers"
php -r '
  $s = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
  $remaining = $s["continuation_expires_at"] - time();
  if ($s["phase"] !== "files-replaced" || $remaining < 1740 || $remaining > 1805) {
    fwrite(STDERR, "Continuation was not renewed after file staging.\n"); exit(1);
  }
' "$target/storage/app/private/update-state.json"

# The first phase is usable with JavaScript disabled, while modern browsers
# should initiate exactly one asynchronous finish request with visible status.
grep -F 'id="continue-update"' "$tmp/stage.html" >/dev/null || { echo "Missing final-step form." >&2; exit 1; }
grep -F 'fetch(form.action' "$tmp/stage.html" >/dev/null || { echo "Automatic final-step handoff is absent." >&2; exit 1; }
grep -F 'id="manual-continue"' "$tmp/stage.html" >/dev/null || { echo "Script-disabled continuation fallback is absent." >&2; exit 1; }

# Reload after stage must resume safely without asking Laravel to authenticate
# an already maintenance-bound browser session.
resume_code="$(curl -sS -H "$https_header" -H "Cookie: $cookie_header" -o "$tmp/resume.html" -w '%{http_code}' "$base_url/update/")"
[[ "$resume_code" == "200" ]] || { echo "Staged update cannot resume (HTTP $resume_code)." >&2; exit 1; }
grep -F 'Resume MCP Gateway Update' "$tmp/resume.html" >/dev/null || { echo "Safe resume form missing." >&2; exit 1; }

# An active finish request must not permit a second POST to enter migrations.
lockfile="$target/storage/app/private/update-execution.lock"
php -r '$h=fopen($argv[1],"c"); flock($h,LOCK_EX); file_put_contents($argv[2],"ready"); usleep(2500000);' "$lockfile" "$tmp/updater-locked" &
holder_pid=$!
for attempt in $(seq 1 30); do
  [[ -f "$tmp/updater-locked" ]] && break
  sleep 0.1
done
[[ -f "$tmp/updater-locked" ]] || { echo "Could not acquire test operation lock." >&2; exit 1; }
busy_code="$(curl -sS -H "$https_header" -H "Cookie: $cookie_header" -o "$tmp/busy.html" -w '%{http_code}' "$base_url/update/")"
[[ "$busy_code" == "202" ]] || { echo "Concurrent update did not show safe progress (HTTP $busy_code)." >&2; exit 1; }
grep -F '<noscript>' "$tmp/busy.html" >/dev/null || { echo "Running updater has no no-JS instructions." >&2; exit 1; }
grep -F 'check update status in this same browser session' "$tmp/busy.html" >/dev/null || { echo "Running no-JS updater lacks a recovery action." >&2; exit 1; }
duplicate_code="$(curl -sS -H "$https_header" -H "Cookie: $cookie_header" --data-urlencode 'action=finish' --data-urlencode "continuation=$continuation" -o "$tmp/duplicate.html" -w '%{http_code}' "$base_url/update/")"
[[ "$duplicate_code" == "202" ]] || { echo "Concurrent finish was not refused (HTTP $duplicate_code)." >&2; exit 1; }
grep -F '<noscript>' "$tmp/duplicate.html" >/dev/null || { echo "Duplicate finish has no no-JS instructions." >&2; exit 1; }
grep -F 'Do not submit Start or Continue again' "$tmp/duplicate.html" >/dev/null || { echo "Duplicate finish lacks a safe manual action." >&2; exit 1; }
wait "$holder_pid"
rm -f "$tmp/updater-locked"

# Simulate a request killed after crossing the migration boundary: the next
# GET must NOT emit a false 403 or permit a second migration.
state_file="$target/storage/app/private/update-state.json"
php -r '$p=$argv[1]; $s=json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR); $s["phase"]="migrate"; $s["migration_started"]=true; file_put_contents($p,json_encode($s,JSON_THROW_ON_ERROR));' "$state_file"
stalled_code="$(curl -sS -H "$https_header" -H "Cookie: $cookie_header" -o "$tmp/stalled.html" -w '%{http_code}' "$base_url/update/")"
[[ "$stalled_code" == "503" ]] || { echo "Interrupted migration did not stop safely (HTTP $stalled_code)." >&2; exit 1; }
grep -Fi 'database may be partially migrated' "$tmp/stalled.html" >/dev/null || { echo "Interrupted migration was not explained." >&2; exit 1; }
if grep -F 'Administrator authentication could not be verified.' "$tmp/stalled.html" >/dev/null; then
  echo "Maintenance reload emitted the misleading authentication failure." >&2; exit 1
fi
php -r '$p=$argv[1]; $s=json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR); $s["phase"]="files-replaced"; $s["migration_started"]=false; file_put_contents($p,json_encode($s,JSON_THROW_ON_ERROR));' "$state_file"

# Reproduce cleanup failure *after* successful migrate/check/up. The current
# backup must remain among the newest three; only the synthetic oldest backup
# is made non-removable to force pruneBackups() to throw.
prune_fixture_root=""
if [[ "$old_version" == "2.0.0" && "$EUID" -ne 0 ]]; then
  prune_fixture_root="$target/storage/app/private/update-backups"
  mkdir -p "$prune_fixture_root/0000-locked/blocked" "$prune_fixture_root/0001-fixture" "$prune_fixture_root/0002-fixture"
  printf 'retained-backup-sentinel\n' > "$prune_fixture_root/0000-locked/blocked/sentinel"
  chmod 0500 "$prune_fixture_root/0000-locked/blocked"
fi

curl -fsS -H "$https_header" -H "Cookie: $cookie_header" \
  --data-urlencode 'action=finish' \
  --data-urlencode "continuation=$continuation" \
  "$base_url/update/" > "$tmp/finish.html"
grep -F 'Update complete.' "$tmp/finish.html" >/dev/null || { cat "$tmp/finish.html" >&2; echo "Browser updater did not report successful completion." >&2; exit 1; }
if [[ -n "$prune_fixture_root" ]]; then
  grep -F 'Old code backups could not be pruned' "$tmp/finish.html" >/dev/null || { echo "Prune failure incorrectly looked like a migration failure." >&2; exit 1; }
  [[ -f "$prune_fixture_root/0000-locked/blocked/sentinel" ]] || { echo "Protected old backup was unexpectedly removed." >&2; exit 1; }
  [[ ! -e "$target/storage/app/private/update-state.json" ]] || { echo "Stale migrate phase survived successful postflight." >&2; exit 1; }
  chmod 0700 "$prune_fixture_root/0000-locked/blocked"
  rm -r "$prune_fixture_root/0000-locked" "$prune_fixture_root/0001-fixture" "$prune_fixture_root/0002-fixture"
fi

[[ "$(tr -d '[:space:]' < "$target/VERSION")" == "$new_version" ]] || { echo "Target VERSION was not updated." >&2; exit 1; }
grep -F 'RewriteRule ^update/?$ - [G,L]' "$target/public/.htaccess" >/dev/null || {
  echo "Installed package does not protect temporary /update URLs against OpenLiteSpeed slash redirect loops." >&2
  exit 1
}
if [[ "$old_version" == "1.2.1" ]]; then
  (
    cd "$target"
    php -r '
      require "vendor/autoload.php";
      $app = require "bootstrap/app.php";
      $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      $db = Illuminate\Support\Facades\DB::class;
      $schema = $db::getSchemaBuilder();
      $owner = $db::table("users")->where("email", "admin@example.test")->first();
      $operator = $db::table("users")->where("email", "operator@example.test")->first();
      $checks = [
        "owner_preserved" => $owner !== null && $owner->role === "owner",
        "operator_preserved" => $operator !== null && $operator->role === "operator",
        "selected_scope_preserved" => $operator !== null && $operator->target_scope_mode === "selected",
        "old_target_assignments_reset" => $db::table("user_target_access")->count() === 0,
        "old_targets_reset" => $db::table("targets")->count() === 0,
        "global_denial_translated" => $operator !== null && $db::table("user_permission_denials")
          ->where("user_id", $operator->id)->where("permission", "targets.view")->count() === 1,
        "oauth_authorizations_reset" => $db::table("oauth_authorizations")->count() === 0,
        "oauth_access_tokens_reset" => $db::table("oauth_access_tokens")->count() === 0,
        "oauth_refresh_tokens_reset" => $db::table("oauth_refresh_tokens")->count() === 0,
        "global_activity_preserved" => $db::table("activity_events")
          ->where("operation", "keep-global-event")->count() === 1,
        "site_activity_reset" => $db::table("activity_events")
          ->where("operation", "discard-site-event")->count() === 0,
        "legacy_site_schema_removed" => !$schema->hasTable("sites") && !$schema->hasTable("site_credentials"),
      ];
      $failed = array_keys(array_filter($checks, static fn (bool $ok): bool => !$ok));
      if ($failed !== []) {
          fwrite(STDERR, "Published v1.2.1 reset/preservation checks failed: ".implode(", ", $failed)."\n");
          exit(1);
      }
      if (is_file("storage/app/private/v121-client-profiles-present")
          && !$schema->hasTable("oauth_client_profiles")) {
          fwrite(STDERR, "Pre-existing OAuth client profiles were not preserved.\n");
          exit(1);
      }
    '
  )
  echo "Seeded v1.2.1 reset boundary: old WordPress/ChatGPT credentials removed; users/roles/global denies and unrelated Activity preserved."
fi
if [[ "$old_version" == "2.0.0" ]]; then
  (
    cd "$target"
    php -r '
      require "vendor/autoload.php";
      $app = require "bootstrap/app.php";
      $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      $db = Illuminate\Support\Facades\DB::class;
      $target = $db::table("targets")->where("target_id", "v200-wordpress")->first();
      $user = $db::table("users")->where("email", "v200-operator@example.test")->first();
      $group = $db::table("target_groups")->where("name", "Existing v2 group")->first();
      $checks = [
        "existing_target_preserved" => $target !== null && $target->connector_type === "wp_ai_bridge",
        "existing_user_preserved" => $user !== null && $user->role === "operator" && $user->target_scope_mode === "selected",
        "existing_group_preserved" => $group !== null,
        "chatgpt_profile_preserved" => $db::table("oauth_client_profiles")->where("profile_key", "chatgpt")->count() === 1,
        "chatgpt_authorization_preserved" => $db::table("oauth_authorizations")
          ->where("client_profile_key", "chatgpt")->where("client_profile_generation", 1)->count() === 1,
      ];
      if ($target !== null && $user !== null && $group !== null) {
        $checks += [
          "target_membership_preserved" => $db::table("target_group_targets")->where("target_group_id", $group->id)->where("target_record_id", $target->id)->count() === 1,
          "user_group_membership_preserved" => $db::table("target_group_users")->where("target_group_id", $group->id)->where("user_id", $user->id)->count() === 1,
          "user_target_allow_preserved" => $db::table("user_target_access")->where("user_id", $user->id)->where("target_record_id", $target->id)->where("allowed", true)->count() === 1,
          "target_denial_preserved" => $db::table("user_target_permission_denials")->where("user_id", $user->id)->where("target_record_id", $target->id)->where("permission", "wordpress.abilities.execute.mutating")->count() === 1,
          "group_denial_preserved" => $db::table("target_group_permission_denials")->where("target_group_id", $group->id)->where("permission", "wordpress.abilities.execute.destructive")->count() === 1,
          "global_denial_preserved" => $db::table("user_permission_denials")->where("user_id", $user->id)->where("permission", "ssh.command.run")->count() === 1,
        ];
        $encrypted = $db::table("target_credentials")->where("target_record_id", $target->id)->where("connector_type", "wp_ai_bridge")->where("purpose", "wordpress_oauth")->value("encrypted_payload");
        $checks["encrypted_credential_preserved"] = is_string($encrypted)
          && Illuminate\Support\Facades\Crypt::decryptString($encrypted) === "v200-test-credential";
      }
      $failed = array_keys(array_filter($checks, static fn (bool $ok): bool => !$ok));
      if ($failed !== []) {
        fwrite(STDERR, "Released v2.0.0 patch-upgrade state preservation failed: ".implode(", ", $failed)."\n");
        exit(1);
      }
    '
  )
  echo "Released v2.0.0 patch-upgrade preservation verified: Target, credential, user/groups, denial layers and ChatGPT grant remain intact."
fi
[[ ! -e "$target/app/obsolete-update-test.txt" ]] || { echo "Stale managed file survived update." >&2; exit 1; }
[[ "$(sha256sum "$target/.env" | awk '{print $1}')" == "$env_hash_before" ]] || { echo ".env changed during update." >&2; exit 1; }
[[ "$(sha256sum "$target/storage/app/private/update-preserve-sentinel.txt" | awk '{print $1}')" == "$private_hash_before" ]] || { echo "Persistent private state changed during update." >&2; exit 1; }
[[ "$(sha256sum "$target/public/.user.ini" | awk '{print $1}')" == "$user_ini_hash_before" ]] || { echo "Successful update changed host-managed public/.user.ini." >&2; exit 1; }
[[ "$(stat -c '%u:%g:%a' "$target/public/.user.ini")" == "$user_ini_meta_before" ]] || { echo "Successful update changed public/.user.ini ownership or mode." >&2; exit 1; }
[[ "$(stat -c '%u:%g:%a' "$target/public")" == "$public_dir_meta_before" ]] || { echo "Successful update changed host-managed public directory ownership or mode." >&2; exit 1; }
[[ "$(sha256sum "$target/public/css/host-managed.txt" | awk '{print $1}')" == "$host_file_hash_before" ]] || { echo "Successful update changed an unknown file inside a shared public directory." >&2; exit 1; }
[[ -f "$target/storage/app/private/installed" ]] || { echo "Installed marker did not survive update." >&2; exit 1; }
[[ ! -e "$target/update" ]] || { echo "Private update staging survived successful cleanup." >&2; exit 1; }
[[ ! -e "$target/public/update" ]] || { echo "Temporary public updater survived successful cleanup." >&2; exit 1; }
[[ ! -e "$canonical_zip" && ! -e "$canonical_zip.sha256" ]] || { echo "Canonical uploaded update archive survived successful cleanup." >&2; exit 1; }
[[ ! -e "$target/storage/app/private/update-state.json" ]] || { echo "Updater state survived successful cleanup." >&2; exit 1; }
[[ "$(find "$target/storage/app/private/update-backups" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ]] || { echo "Expected exactly one updater code backup." >&2; exit 1; }
backup_dir="$(find "$target/storage/app/private/update-backups" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ "$(tr -d '[:space:]' < "$backup_dir/FROM_VERSION")" == "$old_version" ]] || { echo "Code backup does not identify the previous version." >&2; exit 1; }
[[ -f "$backup_dir/files/app/obsolete-update-test.txt" ]] || { echo "Code backup does not contain the previous managed tree." >&2; exit 1; }
[[ -f "$backup_dir/MANAGED_PUBLIC_PATHS" ]] || { echo "Code backup is missing the managed-public ownership manifest." >&2; exit 1; }
[[ ! -e "$backup_dir/files/public/.user.ini" ]] || { echo "Code backup incorrectly captured host-managed public/.user.ini." >&2; exit 1; }
[[ ! -e "$backup_dir/files/public/css/host-managed.txt" ]] || { echo "Code backup incorrectly captured an unknown file inside a shared public directory." >&2; exit 1; }
(
  cd "$target"
  php artisan migrate:status --no-interaction >/dev/null
  php artisan gateway:check --no-interaction >/dev/null
)

post_cleanup_code_without_slash="$(curl -sS -o /dev/null -w '%{http_code}' -H "$https_header" "$base_url/update")"
[[ "$post_cleanup_code_without_slash" == "404" ]] || { echo "Temporary /update endpoint remained reachable (HTTP $post_cleanup_code_without_slash)." >&2; exit 1; }
post_cleanup_code="$(curl -sS -o /dev/null -w '%{http_code}' -H "$https_header" "$base_url/update/")"
[[ "$post_cleanup_code" == "404" ]] || { echo "Temporary /update/ endpoint remained reachable after successful cleanup (HTTP $post_cleanup_code)." >&2; exit 1; }

printf 'Browser update integration verified: %s -> %s\n' "$old_version" "$new_version"
printf '.env/private state and host-managed public files preserved; stale managed files removed; authenticated web flow and one-time cleanup verified.\n'
if [[ "$protected_public_enforced" -eq 1 ]]; then
  printf 'protected public/.user.ini update + pre-migration restore regression verified.\n'
else
  printf 'host-managed public preservation + pre-migration restore logic verified locally; protected deletion resistance is required in CI.\n'
fi
printf 'same/downgrade/tampered/symlink/unsafe preflight cases rejected.\n'
