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
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

old_root_name="$(unzip -Z1 "$old_zip" | awk -F/ 'NF && $1 != "" {print $1; exit}')"
[[ -n "$old_root_name" ]] || { echo "Could not identify old package root." >&2; exit 1; }
unzip -q "$old_zip" -d "$tmp/old"
target="$tmp/old/$old_root_name"
[[ -d "$target" ]] || { echo "Old package root is missing." >&2; exit 1; }

DB_HOST_VALUE="${UPDATE_TEST_DB_HOST:-127.0.0.1}"
DB_PORT_VALUE="${UPDATE_TEST_DB_PORT:-3306}"
DB_DATABASE_VALUE="${UPDATE_TEST_DB_DATABASE:-mcp_gateway_update_test}"
DB_USERNAME_VALUE="${UPDATE_TEST_DB_USERNAME:-mcp_gateway}"
DB_PASSWORD_VALUE="${UPDATE_TEST_DB_PASSWORD:-test-password}"

cat > "$target/.env" <<EOF_ENV
APP_NAME="MCP Gateway Update Test"
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

candidate="$tmp/candidate"
mkdir -p "$candidate"
unzip -q "$update_zip" -d "$candidate"
new_version="$(tr -d '[:space:]' < "$candidate/update/UPDATE_VERSION")"
[[ -f "$candidate/public/update/index.php" && -f "$candidate/update/WebUpdater.php" ]] || { echo "Browser updater files are missing after extraction." >&2; exit 1; }

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
    [$base, $package] = array_slice($argv, 1);
    require $base."/vendor/autoload.php";
    require $package."/WebUpdater.php";
    $updater = new McpGatewayUpdate\WebUpdater($base, $package);
    try {
      $updater->inspect();
      exit(0);
    } catch (Throwable $e) {
      fwrite(STDERR, $e->getMessage()."\n");
      exit(1);
    }
  ' "$base" "$package"
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

guest_code="$(curl -sS -o "$tmp/guest-update.html" -D "$tmp/guest-update.headers" -w '%{http_code}' -H "$https_header" "$base_url/update/")"
[[ "$guest_code" == "302" ]] || { cat "$tmp/guest-update.headers" >&2; echo "Guest browser updater access was not redirected to admin login." >&2; exit 1; }
grep -i '^Location: .*/admin/login' "$tmp/guest-update.headers" >/dev/null || { echo "Guest updater redirect did not target admin login." >&2; exit 1; }

jar="$tmp/admin.cookies"
curl -fsS -c "$jar" -b "$jar" -H "$https_header" "$base_url/admin/login" > "$tmp/login.html"
login_csrf="$(grep -o 'name="_token" value="[^"]*"' "$tmp/login.html" | head -n 1 | sed 's/.*value="\([^"]*\)"/\1/')"
[[ -n "$login_csrf" ]] || { echo "Could not extract admin login CSRF token." >&2; exit 1; }

curl -fsS -L -c "$jar" -b "$jar" -H "$https_header" \
  --data-urlencode "_token=$login_csrf" \
  --data-urlencode 'email=admin@example.test' \
  --data-urlencode 'password=CorrectHorse!234' \
  "$base_url/admin/login" > "$tmp/login-result.html"
grep -F 'Gateway dashboard' "$tmp/login-result.html" >/dev/null || { echo "Administrator login did not reach the dashboard." >&2; exit 1; }

curl -fsS -D "$tmp/update.headers" -c "$jar" -b "$jar" -H "$https_header" "$base_url/update/" > "$tmp/update.html"
grep -F "Installed:</strong> $old_version" "$tmp/update.html" >/dev/null || { echo "Browser updater did not show the installed version." >&2; exit 1; }
grep -F "Target:</strong> $new_version" "$tmp/update.html" >/dev/null || { echo "Browser updater did not show the target version." >&2; exit 1; }
update_csrf="$(grep -o 'name="_token" value="[^"]*"' "$tmp/update.html" | head -n 1 | sed 's/.*value="\([^"]*\)"/\1/')"
update_cookie="$(grep -i '^Set-Cookie: mcp_gateway_update_session=' "$tmp/update.headers" | tail -n 1 | sed -E 's/^[^=]+=([^;]+).*/\1/' | tr -d '\r')"
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

curl -fsS -H "$https_header" -H "Cookie: $cookie_header" \
  --data-urlencode "_token=$update_csrf" \
  --data-urlencode 'action=start' \
  "$base_url/update/" > "$tmp/stage.html"
continuation="$(grep -o 'name="continuation" value="[a-f0-9]*"' "$tmp/stage.html" | head -n 1 | sed 's/.*value="\([a-f0-9]*\)"/\1/')"
[[ "$continuation" =~ ^[a-f0-9]{64}$ ]] || { cat "$tmp/stage.html" >&2; echo "Browser updater did not return a valid continuation token." >&2; exit 1; }

curl -fsS -H "$https_header" -H "Cookie: $cookie_header" \
  --data-urlencode 'action=finish' \
  --data-urlencode "continuation=$continuation" \
  "$base_url/update/" > "$tmp/finish.html"
grep -F 'Update complete.' "$tmp/finish.html" >/dev/null || { cat "$tmp/finish.html" >&2; echo "Browser updater did not report successful completion." >&2; exit 1; }

[[ "$(tr -d '[:space:]' < "$target/VERSION")" == "$new_version" ]] || { echo "Target VERSION was not updated." >&2; exit 1; }
[[ ! -e "$target/app/obsolete-update-test.txt" ]] || { echo "Stale managed file survived update." >&2; exit 1; }
[[ "$(sha256sum "$target/.env" | awk '{print $1}')" == "$env_hash_before" ]] || { echo ".env changed during update." >&2; exit 1; }
[[ "$(sha256sum "$target/storage/app/private/update-preserve-sentinel.txt" | awk '{print $1}')" == "$private_hash_before" ]] || { echo "Persistent private state changed during update." >&2; exit 1; }
[[ -f "$target/storage/app/private/installed" ]] || { echo "Installed marker did not survive update." >&2; exit 1; }
[[ ! -e "$target/update" ]] || { echo "Private update staging survived successful cleanup." >&2; exit 1; }
[[ ! -e "$target/public/update" ]] || { echo "Temporary public updater survived successful cleanup." >&2; exit 1; }
[[ ! -e "$canonical_zip" && ! -e "$canonical_zip.sha256" ]] || { echo "Canonical uploaded update archive survived successful cleanup." >&2; exit 1; }
[[ ! -e "$target/storage/app/private/update-state.json" ]] || { echo "Updater state survived successful cleanup." >&2; exit 1; }
[[ "$(find "$target/storage/app/private/update-backups" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ]] || { echo "Expected exactly one updater code backup." >&2; exit 1; }
backup_dir="$(find "$target/storage/app/private/update-backups" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ "$(tr -d '[:space:]' < "$backup_dir/FROM_VERSION")" == "$old_version" ]] || { echo "Code backup does not identify the previous version." >&2; exit 1; }
[[ -f "$backup_dir/files/app/obsolete-update-test.txt" ]] || { echo "Code backup does not contain the previous managed tree." >&2; exit 1; }
(
  cd "$target"
  php artisan migrate:status --no-interaction >/dev/null
  php artisan gateway:check --no-interaction >/dev/null
)

post_cleanup_code="$(curl -sS -o /dev/null -w '%{http_code}' -H "$https_header" "$base_url/update/")"
[[ "$post_cleanup_code" == "404" ]] || { echo "Temporary /update/ endpoint remained reachable after successful cleanup (HTTP $post_cleanup_code)." >&2; exit 1; }

printf 'Browser update integration verified: %s -> %s\n' "$old_version" "$new_version"
printf '.env/private state preserved; stale files removed; authenticated web flow and one-time cleanup verified.\n'
printf 'same/downgrade/tampered/symlink/unsafe preflight cases rejected.\n'
