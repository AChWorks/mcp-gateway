#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: bash bin/test-update-package.sh <update-zip> <update-root-name> <old-deployment-zip>" >&2
  exit 2
fi

update_zip="$1"
update_root_name="$2"
old_zip="$3"

for command in unzip php find sha256sum mktemp cp rm grep; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required test command is unavailable: $command" >&2; exit 1; }
done
[[ -f "$update_zip" ]] || { echo "Missing update ZIP: $update_zip" >&2; exit 1; }
[[ -f "$old_zip" ]] || { echo "Missing old deployment ZIP: $old_zip" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$update_zip" -d "$tmp/update"
update_root="$tmp/update/$update_root_name"
[[ -x "$update_root/update.sh" ]] || { echo "Updater missing after extraction." >&2; exit 1; }

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
APP_ENV=production
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
SESSION_SECURE_COOKIE=true
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
  printf '{"installed":true}\n' > storage/app/private/installed
  printf 'persistent-private-state\n' > storage/app/private/update-preserve-sentinel.txt
  printf 'stale-managed-file\n' > app/obsolete-update-test.txt
)

env_hash_before="$(sha256sum "$target/.env" | awk '{print $1}')"
private_hash_before="$(sha256sum "$target/storage/app/private/update-preserve-sentinel.txt" | awk '{print $1}')"
old_version="$(tr -d '[:space:]' < "$target/VERSION")"
new_version="$(tr -d '[:space:]' < "$update_root/UPDATE_VERSION")"

bash "$update_root/update.sh" "$target"

[[ "$(tr -d '[:space:]' < "$target/VERSION")" == "$new_version" ]] || { echo "Target VERSION was not updated." >&2; exit 1; }
[[ ! -e "$target/app/obsolete-update-test.txt" ]] || { echo "Stale managed file survived update." >&2; exit 1; }
[[ "$(sha256sum "$target/.env" | awk '{print $1}')" == "$env_hash_before" ]] || { echo ".env changed during update." >&2; exit 1; }
[[ "$(sha256sum "$target/storage/app/private/update-preserve-sentinel.txt" | awk '{print $1}')" == "$private_hash_before" ]] || { echo "Persistent private state changed during update." >&2; exit 1; }
[[ -f "$target/storage/app/private/installed" ]] || { echo "Installed marker did not survive update." >&2; exit 1; }
[[ "$(find "$target/storage/app/private/update-backups" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ]] || { echo "Expected exactly one updater backup after first update." >&2; exit 1; }
backup_dir="$(find "$target/storage/app/private/update-backups" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ "$(tr -d '[:space:]' < "$backup_dir/FROM_VERSION")" == "$old_version" ]] || { echo "Code backup does not identify the previous version." >&2; exit 1; }
[[ -f "$backup_dir/files/app/obsolete-update-test.txt" ]] || { echo "Code backup does not contain the previous managed tree." >&2; exit 1; }
(
  cd "$target"
  php artisan migrate:status --no-interaction >/dev/null
  php artisan gateway:check --no-interaction >/dev/null
)

if bash "$update_root/update.sh" "$target" >"$tmp/same.out" 2>&1; then
  echo "Same-version update unexpectedly succeeded." >&2
  exit 1
fi
grep -F "target version must be newer" "$tmp/same.out" >/dev/null || { echo "Same-version rejection was not actionable." >&2; exit 1; }

unsafe_target="$tmp/unsafe-target"
mkdir -p "$unsafe_target"
if bash "$update_root/update.sh" "$unsafe_target" >"$tmp/unsafe.out" 2>&1; then
  echo "Unsafe target unexpectedly succeeded." >&2
  exit 1
fi
grep -F "does not look like an installed deployment package" "$tmp/unsafe.out" >/dev/null || { echo "Unsafe target rejection was not actionable." >&2; exit 1; }

cp -a "$update_root" "$tmp/tampered-update"
printf 'tampered\n' >> "$tmp/tampered-update/payload/VERSION"
if bash "$tmp/tampered-update/update.sh" "$target" >"$tmp/tampered.out" 2>&1; then
  echo "Tampered package unexpectedly succeeded." >&2
  exit 1
fi
grep -F "checksum validation failed" "$tmp/tampered.out" >/dev/null || { echo "Tampered package rejection was not actionable." >&2; exit 1; }

cp -a "$update_root" "$tmp/symlink-update"
ln -s /etc/passwd "$tmp/symlink-update/payload/unsafe-link"
if bash "$tmp/symlink-update/update.sh" "$target" >"$tmp/symlink.out" 2>&1; then
  echo "Symlink package unexpectedly succeeded." >&2
  exit 1
fi
grep -F "symbolic link" "$tmp/symlink.out" >/dev/null || { echo "Symlink package rejection was not actionable." >&2; exit 1; }

# Downgrade protection is tested against a structurally valid target identity.
printf '99.99.99\n' > "$target/VERSION"
if bash "$update_root/update.sh" "$target" >"$tmp/downgrade.out" 2>&1; then
  echo "Downgrade unexpectedly succeeded." >&2
  exit 1
fi
grep -F "target version must be newer" "$tmp/downgrade.out" >/dev/null || { echo "Downgrade rejection was not actionable." >&2; exit 1; }

printf 'Update integration verified: %s -> %s\n' "$old_version" "$new_version"
printf '.env/private state preserved; stale managed files removed; invalid/same/downgrade/unsafe cases rejected.\n'
