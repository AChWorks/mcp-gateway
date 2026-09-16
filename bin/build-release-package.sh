#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: bash bin/build-release-package.sh <package-name> [dist-directory]" >&2
  exit 2
fi

package="$1"
if [[ ! "$package" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Package name contains unsupported characters: $package" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${2:-$repo_root/dist}"
mkdir -p "$dist_dir"
dist_dir="$(cd "$dist_dir" && pwd)"
destination="$dist_dir/$package"
zip_path="$dist_dir/$package.zip"
checksum_path="$zip_path.sha256"

for command in composer php zip sha256sum find sort touch; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is unavailable: $command" >&2
    exit 1
  }
done

rm -rf "$destination"
rm -f "$zip_path" "$checksum_path" "$dist_dir/.$package.files"
mkdir -p "$destination"

cp -a \
  "$repo_root/app" \
  "$repo_root/config" \
  "$repo_root/public" \
  "$repo_root/resources" \
  "$repo_root/routes" \
  "$destination/"

cp -a \
  "$repo_root/artisan" \
  "$repo_root/.env.example" \
  "$repo_root/LICENSE" \
  "$repo_root/VERSION" \
  "$repo_root/composer.json" \
  "$repo_root/composer.lock" \
  "$destination/"

mkdir -p "$destination/bootstrap/cache"
cp -a "$repo_root/bootstrap/app.php" "$repo_root/bootstrap/providers.php" "$destination/bootstrap/"

mkdir -p "$destination/database/migrations"
cp -a "$repo_root/database/migrations/." "$destination/database/migrations/"

mkdir -p \
  "$destination/storage/app/private" \
  "$destination/storage/app/public" \
  "$destination/storage/framework/cache/data" \
  "$destination/storage/framework/mcp-sessions" \
  "$destination/storage/framework/sessions" \
  "$destination/storage/framework/views" \
  "$destination/storage/logs"

(
  cd "$destination"
  composer install --no-dev --no-interaction --prefer-dist --no-progress --optimize-autoloader
  composer check-platform-reqs --no-dev
)

php "$repo_root/bin/prune-production-vendor.php" "$destination/vendor"

# The deployment artifact is not a source checkout. Keep the runtime manifest
# Laravel needs, but remove source-development sections and source lock metadata.
php -r '
$path = $argv[1];
$data = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
unset($data["require-dev"], $data["autoload-dev"], $data["scripts"]);
$psr4 = $data["autoload"]["psr-4"] ?? [];
$appMappings = [];
foreach ($psr4 as $namespace => $paths) {
    foreach ((array) $paths as $candidate) {
        if (trim(str_replace("\\\\", "/", (string) $candidate), "/") === "app") {
            $appMappings[$namespace] = $candidate;
        }
    }
}
if (count($appMappings) !== 1) {
    fwrite(STDERR, "Could not identify one application PSR-4 mapping for the runtime composer manifest.\n");
    exit(1);
}
$data["autoload"] = ["psr-4" => $appMappings];
file_put_contents(
    $path,
    json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n",
);
' "$destination/composer.json"
rm -f "$destination/composer.lock"

# Never inherit generated source/test state. Runtime directories are shipped empty.
rm -rf "$destination/storage"
mkdir -p \
  "$destination/storage/app/private" \
  "$destination/storage/app/public" \
  "$destination/storage/framework/cache/data" \
  "$destination/storage/framework/mcp-sessions" \
  "$destination/storage/framework/sessions" \
  "$destination/storage/framework/views" \
  "$destination/storage/logs"

mapfile -t unexpected_cache < <(
  find "$destination/bootstrap/cache" -mindepth 1 -maxdepth 1 \
    ! -name 'packages.php' ! -name 'services.php' -printf '%f\n' | sort
)
if (( ${#unexpected_cache[@]} > 0 )); then
  printf 'Unexpected bootstrap/cache content after clean production install:\n' >&2
  printf '  %s\n' "${unexpected_cache[@]}" >&2
  exit 1
fi

for required_cache in packages.php services.php; do
  [[ -f "$destination/bootstrap/cache/$required_cache" ]] || {
    echo "Missing generated production bootstrap cache: $required_cache" >&2
    exit 1
  }
done

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}"
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "Invalid SOURCE_DATE_EPOCH: $source_date_epoch" >&2
  exit 1
fi
find "$destination" -exec touch -h -d "@$source_date_epoch" {} +

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
