#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  echo "Usage: bash update.sh /absolute/path/to/existing-mcp-gateway" >&2
  exit 2
fi

for command in php cp rm mkdir find sort sha256sum date awk grep; do
  command -v "$command" >/dev/null 2>&1 || fail "Required command is unavailable: $command"
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
payload="$script_dir/payload"
manifest="$script_dir/manifest.sha256"
update_version_file="$script_dir/UPDATE_VERSION"

[[ -d "$payload" ]] || fail "Update payload directory is missing."
[[ -f "$manifest" ]] || fail "Update manifest is missing."
[[ -f "$update_version_file" ]] || fail "UPDATE_VERSION is missing."

if find "$script_dir" -type l -print -quit | grep -q .; then
  fail "Update package contains a symbolic link and was rejected."
fi

(
  cd "$script_dir"
  sha256sum --check --strict manifest.sha256 >/dev/null
) || fail "Update package checksum validation failed. Re-download the named update ZIP."

expected_payload_top="$(cat <<'LIST'
.env.example
LICENSE
VERSION
app
artisan
bootstrap
composer.json
config
database
public
resources
routes
vendor
LIST
)"
actual_payload_top="$(find "$payload" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
[[ "$actual_payload_top" == "$expected_payload_top" ]] || fail "Update payload layout is invalid."
[[ ! -e "$payload/.env" ]] || fail "Update payload must never contain a production .env file."
[[ ! -e "$payload/storage" ]] || fail "Update payload must never contain persistent storage."
[[ -f "$payload/vendor/autoload.php" ]] || fail "Update payload is missing production Composer dependencies."

new_version="$(tr -d '[:space:]' < "$update_version_file")"
payload_version="$(tr -d '[:space:]' < "$payload/VERSION")"
[[ "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Update version is not a semantic version."
[[ "$payload_version" == "$new_version" ]] || fail "Update metadata and payload version do not match."

target_input="$1"
[[ "$target_input" = /* ]] || fail "Target path must be absolute."
[[ -d "$target_input" ]] || fail "Target directory does not exist: $target_input"
target="$(cd "$target_input" && pwd -P)"
[[ "$target" != "/" ]] || fail "Refusing to use filesystem root as the update target."

case "$script_dir/" in
  "$target/"*) fail "Extract the update package outside the existing Gateway directory before running it." ;;
esac

for required in .env VERSION artisan vendor/autoload.php storage/app/private/installed; do
  [[ -e "$target/$required" ]] || fail "Target does not look like an installed deployment package; missing: $required"
done
[[ ! -e "$target/.git" && ! -e "$target/composer.lock" ]] || fail "This updater is for deployment-ZIP installations. Use the documented source/Composer upgrade path for a source checkout."
[[ -w "$target" && -w "$target/storage/app/private" ]] || fail "Target or persistent private storage is not writable by the current user."

current_version="$(tr -d '[:space:]' < "$target/VERSION")"
[[ "$current_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Installed VERSION is invalid."
# shellcheck disable=SC2016
# PHP receives its own argv; shell expansion is intentionally disabled.
php -r 'exit(version_compare($argv[1], $argv[2], "<") ? 0 : 1);' "$current_version" "$new_version" \
  || fail "Refusing update from $current_version to $new_version: target version must be newer than the installed version."

managed=(
  .env.example
  LICENSE
  VERSION
  app
  artisan
  bootstrap
  composer.json
  config
  database
  public
  resources
  routes
  vendor
)

for entry in "${managed[@]}" storage storage/app storage/app/private; do
  [[ ! -L "$target/$entry" ]] || fail "Target contains an unsupported top-level/persistent symlink: $entry"
done

printf 'MCP Gateway manual update\n'
printf '  Installed: %s\n' "$current_version"
printf '  Updating to: %s\n' "$new_version"
printf '  Target: %s\n' "$target"

printf 'Preflight: validating current Gateway...\n'
(
  cd "$target"
  php artisan gateway:check --no-interaction
) || fail "Current Gateway preflight failed. No files were changed."

backup_base="$target/storage/app/private/update-backups"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$backup_base/${timestamp}-$$-${current_version}-to-${new_version}"
phase="before-mutation"
maintenance_entered=0
backup_preparing=0
backup_created=0
files_mutated=0
migration_started=0

prune_backups() {
  [[ -d "$backup_base" ]] || return 0
  mapfile -t old_backups < <(find "$backup_base" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort -r)
  if (( ${#old_backups[@]} > 3 )); then
    for name in "${old_backups[@]:3}"; do
      rm -rf -- "${backup_base:?}/$name"
    done
  fi
}

restore_files() {
  printf 'Restoring application files from %s ...\n' "$backup" >&2
  for entry in "${managed[@]}"; do
    rm -rf -- "${target:?}/$entry"
  done
  cp -a "$backup/files/." "$target/"
}

on_error() {
  status=$?
  trap - ERR
  set +e
  printf 'Update failed during phase: %s\n' "$phase" >&2

  if [[ $files_mutated -eq 1 && $migration_started -eq 0 ]]; then
    if restore_files; then
      if [[ $maintenance_entered -eq 1 ]]; then
        if (cd "$target" && php artisan up --no-interaction >/dev/null 2>&1); then
          maintenance_entered=0
        else
          printf 'Application files were restored, but maintenance mode could not be cleared automatically.\n' >&2
        fi
      fi
      printf 'Application files were restored automatically. Persistent .env/storage were never replaced.\n' >&2
    else
      printf 'Automatic application-file restore failed. Leave maintenance mode enabled and recover from: %s\n' "$backup" >&2
    fi
  elif [[ $migration_started -eq 1 ]]; then
    printf 'Automatic code rollback was not attempted because database migration may have started.\n' >&2
    printf 'Keep the application in maintenance mode and inspect the failure before choosing rollback or roll-forward.\n' >&2
    printf 'Code backup: %s\n' "$backup" >&2
  else
    if [[ $backup_preparing -eq 1 && $backup_created -eq 0 ]]; then
      rm -rf -- "${backup:?}"
    fi
    if [[ $maintenance_entered -eq 1 ]]; then
      if (cd "$target" && php artisan up --no-interaction >/dev/null 2>&1); then
        maintenance_entered=0
      else
        printf 'No managed files changed, but maintenance mode could not be cleared automatically.\n' >&2
      fi
    fi
    printf 'No application-managed files were changed.\n' >&2
  fi

  if [[ $backup_created -eq 1 ]]; then
    prune_backups
  fi
  exit "$status"
}
trap on_error ERR

phase="maintenance"
(
  cd "$target"
  php artisan down --retry=60 --no-interaction
)
maintenance_entered=1

phase="backup"
backup_preparing=1
mkdir -p "$backup/files"
for entry in "${managed[@]}"; do
  if [[ -e "$target/$entry" || -L "$target/$entry" ]]; then
    cp -a "$target/$entry" "$backup/files/"
  fi
done
printf '%s\n' "$current_version" > "$backup/FROM_VERSION"
printf '%s\n' "$new_version" > "$backup/TO_VERSION"
backup_created=1
backup_preparing=0

phase="replace-files"
files_mutated=1
for entry in "${managed[@]}"; do
  rm -rf -- "${target:?}/$entry"
done
for entry in "${managed[@]}"; do
  cp -a "$payload/$entry" "$target/"
done

if [[ ! -f "$target/.env" ]]; then
  echo "Persistent .env disappeared unexpectedly." >&2
  false
fi
if [[ ! -f "$target/storage/app/private/installed" ]]; then
  echo "Installed marker disappeared unexpectedly." >&2
  false
fi

phase="clear-cache"
(
  cd "$target"
  php artisan optimize:clear --no-interaction
)

phase="migrate"
migration_started=1
(
  cd "$target"
  php artisan migrate --force --no-interaction
)

phase="postflight"
(
  cd "$target"
  php artisan gateway:check --no-interaction
)

phase="resume"
(
  cd "$target"
  php artisan up --no-interaction
)
maintenance_entered=0

phase="cleanup"
prune_backups

trap - ERR
printf 'Update complete: MCP Gateway %s -> %s\n' "$current_version" "$new_version"
printf 'Code backup retained at: %s\n' "$backup"
printf 'Persistent .env and storage were preserved.\n'
