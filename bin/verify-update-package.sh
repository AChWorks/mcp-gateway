#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: bash bin/verify-update-package.sh <zip-path>" >&2
  exit 2
fi

zip_path="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$zip_path" ]] || { echo "Update ZIP does not exist: $zip_path" >&2; exit 1; }

for command in unzip php find sort diff awk grep mktemp sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required verification command is unavailable: $command" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
list="$tmp/zip-list.txt"
unzip -Z1 "$zip_path" > "$list"

if grep -E '(^|/)\.\.(/|$)' "$list" >/dev/null || grep -F "\\" "$list" >/dev/null || grep -E '^/' "$list" >/dev/null; then
  echo "Update ZIP contains an unsafe path." >&2
  exit 1
fi

while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  case "$entry" in
    update|update/|update/*|public/update|public/update/|public/update/*) ;;
    *)
      echo "Update ZIP contains an unexpected path: $entry" >&2
      exit 1
      ;;
  esac
done < "$list"

unzip -q "$zip_path" -d "$tmp/extracted"
root="$tmp/extracted"
[[ -d "$root/update/payload" ]] || { echo "Extracted private update payload is missing." >&2; exit 1; }
[[ -f "$root/public/update/index.php" ]] || { echo "Temporary browser updater entrypoint is missing." >&2; exit 1; }
[[ -f "$root/update/WebUpdater.php" ]] || { echo "Browser update engine is missing." >&2; exit 1; }
[[ -f "$root/update/UPDATE_VERSION" ]] || { echo "UPDATE_VERSION is missing." >&2; exit 1; }
[[ -f "$root/update/PUBLIC_ENTRY_SHA256" ]] || { echo "PUBLIC_ENTRY_SHA256 is missing." >&2; exit 1; }
[[ -f "$root/update/manifest.sha256" ]] || { echo "Update manifest is missing." >&2; exit 1; }

php -l "$root/update/WebUpdater.php" >/dev/null
php -l "$root/public/update/index.php" >/dev/null

if find "$root/update" "$root/public/update" -type l -print | grep . >/dev/null; then
  echo "Update ZIP must not contain symbolic links." >&2
  exit 1
fi

expected_public_hash="$(tr -d '[:space:]' < "$root/update/PUBLIC_ENTRY_SHA256")"
actual_public_hash="$(sha256sum "$root/public/update/index.php" | awk '{print $1}')"
[[ "$expected_public_hash" =~ ^[a-f0-9]{64}$ && "$expected_public_hash" == "$actual_public_hash" ]] || {
  echo "Temporary public updater integrity check failed." >&2
  exit 1
}

(
  cd "$root/update"
  sha256sum --check --strict manifest.sha256 >/dev/null
)

version="$(tr -d '[:space:]' < "$root/update/UPDATE_VERSION")"
payload_version="$(tr -d '[:space:]' < "$root/update/payload/VERSION")"
repo_version="$(tr -d '[:space:]' < "$repo_root/VERSION")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid update semantic version: $version" >&2; exit 1; }
[[ "$version" == "$payload_version" && "$version" == "$repo_version" ]] || { echo "Update/repository/payload versions do not match." >&2; exit 1; }

cat > "$tmp/expected-payload-top.txt" <<'EOF_PAYLOAD'
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
EOF_PAYLOAD
find "$root/update/payload" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort > "$tmp/actual-payload-top.txt"
diff -u "$tmp/expected-payload-top.txt" "$tmp/actual-payload-top.txt"

[[ ! -e "$root/update/payload/.env" ]] || { echo "Update payload must not contain .env." >&2; exit 1; }
[[ ! -e "$root/update/payload/storage" ]] || { echo "Update payload must not contain storage." >&2; exit 1; }
[[ -f "$root/update/payload/vendor/autoload.php" ]] || { echo "Update payload is missing vendor/autoload.php." >&2; exit 1; }
[[ ! -e "$root/update/payload/composer.lock" ]] || { echo "Update payload must not contain source composer.lock." >&2; exit 1; }
[[ ! -e "$root/update/payload/vendor/bin" ]] || { echo "Update payload must not contain vendor/bin." >&2; exit 1; }

php "$repo_root/bin/prune-production-vendor.php" --check "$root/update/payload/vendor"

printf 'Browser update ZIP verified: %s\n' "$zip_path"
printf 'Version: %s\n' "$version"
printf 'Files: %s\n' "$(find "$root/update" "$root/public/update" -type f | wc -l)"
