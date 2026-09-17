#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: bash bin/build-update-package.sh <update-package-name> <runtime-tree> [dist-directory]" >&2
  exit 2
fi

package="$1"
runtime_tree="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${3:-$repo_root/dist}"

[[ "$package" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid update package name: $package" >&2; exit 2; }
[[ -d "$runtime_tree" ]] || { echo "Runtime tree does not exist: $runtime_tree" >&2; exit 1; }
runtime_tree="$(cd "$runtime_tree" && pwd -P)"
mkdir -p "$dist_dir"
dist_dir="$(cd "$dist_dir" && pwd -P)"

for command in zip sha256sum find sort cp rm touch; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required command is unavailable: $command" >&2; exit 1; }
done

version="$(tr -d '[:space:]' < "$repo_root/VERSION")"
source_version="$(tr -d '[:space:]' < "$runtime_tree/VERSION")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Repository VERSION is invalid: $version" >&2; exit 1; }
[[ "$source_version" == "$version" ]] || { echo "Runtime tree VERSION ($source_version) does not match repository VERSION ($version)." >&2; exit 1; }

root="$dist_dir/$package"
zip_path="$dist_dir/$package.zip"
rm -rf "$root"
rm -f "$zip_path" "$zip_path.sha256" "$dist_dir/.$package.files"
mkdir -p "$root/payload"

for entry in .env.example LICENSE VERSION app artisan bootstrap composer.json config database public resources routes vendor; do
  [[ -e "$runtime_tree/$entry" ]] || { echo "Runtime tree is missing required entry: $entry" >&2; exit 1; }
  cp -a "$runtime_tree/$entry" "$root/payload/"
done

cp -a "$repo_root/bin/mcp-gateway-update.sh" "$root/update.sh"
chmod +x "$root/update.sh"
printf '%s\n' "$version" > "$root/UPDATE_VERSION"

(
  cd "$root"
  {
    printf '%s\0' UPDATE_VERSION update.sh
    find payload -type f -print0 | LC_ALL=C sort -z
  } | xargs -0 sha256sum > manifest.sha256
)

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || { echo "Invalid SOURCE_DATE_EPOCH: $source_date_epoch" >&2; exit 1; }
find "$root" -exec touch -h -d "@$source_date_epoch" {} +

(
  cd "$dist_dir"
  list_file=".$package.files"
  find "$package" -print | LC_ALL=C sort > "$list_file"
  zip -X -q "$package.zip" -@ < "$list_file"
  rm -f "$list_file"
  sha256sum "$package.zip" > "$package.zip.sha256"
)

printf 'Built %s\n' "$zip_path"
printf 'SHA256: '
sha256sum "$zip_path" | awk '{print $1}'
