#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash bin/verify-update-package.sh <zip-path> <package-root-name>" >&2
  exit 2
fi

zip_path="$1"
package="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$zip_path" ]] || { echo "Update ZIP does not exist: $zip_path" >&2; exit 1; }
[[ "$package" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid package root name: $package" >&2; exit 2; }

for command in unzip bash php find sort diff awk grep mktemp sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required verification command is unavailable: $command" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
list="$tmp/zip-list.txt"
unzip -Z1 "$zip_path" > "$list"

if grep -E '(^|/)\.\.(/|$)' "$list" >/dev/null || grep -F "\\" "$list" >/dev/null; then
  echo "Update ZIP contains an unsafe path." >&2
  exit 1
fi
if awk -F/ -v root="$package" '$1 != root { print; bad=1 } END { exit bad ? 0 : 1 }' "$list" | grep . >/dev/null; then
  echo "Update ZIP contains entries outside the expected package root." >&2
  exit 1
fi

cat > "$tmp/expected-top-level.txt" <<'EOF_TOP'
UPDATE_VERSION
manifest.sha256
payload
update.sh
EOF_TOP
awk -F/ -v root="$package" '$1 == root && NF >= 2 && $2 != "" { print $2 }' "$list" | sort -u > "$tmp/actual-top-level.txt"
diff -u "$tmp/expected-top-level.txt" "$tmp/actual-top-level.txt"

unzip -q "$zip_path" -d "$tmp/extracted"
root="$tmp/extracted/$package"
[[ -d "$root" ]] || { echo "Extracted update package root is missing." >&2; exit 1; }
[[ -x "$root/update.sh" ]] || { echo "Update runner is not executable." >&2; exit 1; }
bash -n "$root/update.sh"

if find "$root" -type l -print | grep . >/dev/null; then
  echo "Update ZIP must not contain symbolic links." >&2
  exit 1
fi

(
  cd "$root"
  sha256sum --check --strict manifest.sha256 >/dev/null
)

version="$(tr -d '[:space:]' < "$root/UPDATE_VERSION")"
payload_version="$(tr -d '[:space:]' < "$root/payload/VERSION")"
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
find "$root/payload" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort > "$tmp/actual-payload-top.txt"
diff -u "$tmp/expected-payload-top.txt" "$tmp/actual-payload-top.txt"

[[ ! -e "$root/payload/.env" ]] || { echo "Update payload must not contain .env." >&2; exit 1; }
[[ ! -e "$root/payload/storage" ]] || { echo "Update payload must not contain storage." >&2; exit 1; }
[[ -f "$root/payload/vendor/autoload.php" ]] || { echo "Update payload is missing vendor/autoload.php." >&2; exit 1; }
[[ ! -e "$root/payload/composer.lock" ]] || { echo "Update payload must not contain source composer.lock." >&2; exit 1; }
[[ ! -e "$root/payload/vendor/bin" ]] || { echo "Update payload must not contain vendor/bin." >&2; exit 1; }

php "$repo_root/bin/prune-production-vendor.php" --check "$root/payload/vendor"

printf 'Update ZIP verified: %s\n' "$zip_path"
printf 'Version: %s\n' "$version"
printf 'Files: %s\n' "$(find "$root" -type f | wc -l)"
