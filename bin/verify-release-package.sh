#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash bin/verify-release-package.sh <zip-path> <package-root-name>" >&2
  exit 2
fi

zip_path="$1"
package="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ -f "$zip_path" ]] || { echo "ZIP does not exist: $zip_path" >&2; exit 1; }
[[ "$package" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid package root name: $package" >&2; exit 2; }

for command in unzip php find sort diff awk grep mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required verification command is unavailable: $command" >&2
    exit 1
  }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
list="$tmp/zip-list.txt"
unzip -Z1 "$zip_path" > "$list"

if grep -E '(^|/)\.\.(/|$)' "$list" >/dev/null || grep -F '\\' "$list" >/dev/null; then
  echo "Deployment ZIP contains an unsafe path." >&2
  exit 1
fi

if awk -F/ -v root="$package" '$1 != root { print; bad=1 } END { exit bad ? 0 : 1 }' "$list" | grep . >/dev/null; then
  echo "Deployment ZIP contains entries outside the expected package root." >&2
  exit 1
fi

cat > "$tmp/expected-top-level.txt" <<'EOF'
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
storage
vendor
EOF

awk -F/ -v root="$package" '$1 == root && NF >= 2 && $2 != "" { print $2 }' "$list" \
  | sort -u > "$tmp/actual-top-level.txt"
diff -u "$tmp/expected-top-level.txt" "$tmp/actual-top-level.txt"

required_entries=(
  "$package/.env.example"
  "$package/LICENSE"
  "$package/VERSION"
  "$package/artisan"
  "$package/composer.json"
  "$package/app/"
  "$package/bootstrap/"
  "$package/bootstrap/app.php"
  "$package/bootstrap/providers.php"
  "$package/bootstrap/cache/packages.php"
  "$package/bootstrap/cache/services.php"
  "$package/config/"
  "$package/database/migrations/"
  "$package/public/"
  "$package/public/.htaccess"
  "$package/public/index.php"
  "$package/public/install.php"
  "$package/resources/"
  "$package/routes/"
  "$package/storage/framework/mcp-sessions/"
  "$package/vendor/autoload.php"
  "$package/vendor/composer/installed.php"
)

for entry in "${required_entries[@]}"; do
  grep -Fx "$entry" "$list" >/dev/null || {
    echo "Deployment ZIP is missing required entry: $entry" >&2
    exit 1
  }
done

unzip -q "$zip_path" -d "$tmp/extracted"
root="$tmp/extracted/$package"
[[ -d "$root" ]] || { echo "Extracted package root is missing." >&2; exit 1; }

if find "$root" -type l -print | grep . >/dev/null; then
  echo "Deployment ZIP must not contain symbolic links." >&2
  exit 1
fi

[[ ! -e "$root/composer.lock" ]] || { echo "Source composer.lock must not be shipped in the deployment artifact." >&2; exit 1; }
[[ ! -e "$root/vendor/bin" ]] || { echo "vendor/bin must not be shipped in the deployment artifact." >&2; exit 1; }
[[ ! -e "$root/vendor/composer/installed.json" ]] || { echo "vendor/composer/installed.json must not be shipped in the deployment artifact." >&2; exit 1; }

mapfile -t environment_files < <(find "$root" -type f -name '.env*' -printf '%P\n' | sort)
if [[ ${#environment_files[@]} -ne 1 || "${environment_files[0]}" != '.env.example' ]]; then
  echo "Deployment ZIP may contain only the root .env.example environment file." >&2
  printf '  %s\n' "${environment_files[@]}" >&2
  exit 1
fi

if find "$root" \
  \( -name '.git' -o -name '.github' -o -name '.gitlab' -o -name '.circleci' \
     -o -name '.gitignore' -o -name '.gitattributes' -o -name '.editorconfig' \
     -o -name 'phpunit.xml*' -o -name 'phpstan.neon*' -o -name 'psalm.xml*' \
     -o -name 'infection.json*' -o -name 'phpcs.xml*' \) \
  -print | grep . >/dev/null; then
  echo "Deployment ZIP contains repository/development metadata." >&2
  exit 1
fi

cat > "$tmp/expected-storage-dirs.txt" <<'EOF'
app
app/private
app/public
framework
framework/cache
framework/cache/data
framework/mcp-sessions
framework/sessions
framework/views
logs
EOF
find "$root/storage" -mindepth 1 -type d -printf '%P\n' | sort > "$tmp/actual-storage-dirs.txt"
diff -u "$tmp/expected-storage-dirs.txt" "$tmp/actual-storage-dirs.txt"
if find "$root/storage" -type f -print | grep . >/dev/null; then
  echo "Deployment storage must contain directory scaffolding only, never generated runtime/test state." >&2
  exit 1
fi

cat > "$tmp/expected-bootstrap-cache.txt" <<'EOF'
packages.php
services.php
EOF
find "$root/bootstrap/cache" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort > "$tmp/actual-bootstrap-cache.txt"
diff -u "$tmp/expected-bootstrap-cache.txt" "$tmp/actual-bootstrap-cache.txt"
if find "$root/bootstrap/cache" -mindepth 1 -maxdepth 1 -type d -print | grep . >/dev/null; then
  echo "bootstrap/cache contains unexpected directories." >&2
  exit 1
fi

mapfile -t database_top < <(find "$root/database" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ ${#database_top[@]} -ne 1 || "${database_top[0]}" != 'migrations' ]]; then
  echo "Deployment database directory may contain migrations only." >&2
  printf '  %s\n' "${database_top[@]}" >&2
  exit 1
fi
if ! find "$root/database/migrations" -maxdepth 1 -type f -name '*.php' -print -quit | grep . >/dev/null; then
  echo "Deployment package contains no migrations." >&2
  exit 1
fi
if find "$root/database/migrations" -type f ! -name '*.php' -print | grep . >/dev/null; then
  echo "Deployment migration directory contains a non-PHP artifact." >&2
  exit 1
fi

php -r '
$path = $argv[1];
$data = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
foreach (["require-dev", "autoload-dev", "scripts"] as $forbidden) {
    if (array_key_exists($forbidden, $data)) {
        fwrite(STDERR, "Runtime composer.json contains forbidden development section: {$forbidden}\n");
        exit(1);
    }
}
$psr4 = $data["autoload"]["psr-4"] ?? [];
if (count($psr4) !== 1) {
    fwrite(STDERR, "Runtime composer.json must expose exactly one application PSR-4 mapping.\n");
    exit(1);
}
$paths = (array) array_values($psr4)[0];
if (count($paths) !== 1 || trim(str_replace("\\\\", "/", (string) $paths[0]), "/") !== "app") {
    fwrite(STDERR, "Runtime composer.json application PSR-4 mapping is invalid.\n");
    exit(1);
}
' "$root/composer.json"

php "$repo_root/bin/prune-production-vendor.php" --check "$root/vendor"

license_count="$(find "$root/vendor" -type f \
  \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) \
  | wc -l)"
if [[ "$license_count" -lt 1 ]]; then
  echo "Dependency license/notice material is unexpectedly absent." >&2
  exit 1
fi

php -l "$root/public/install.php" >/dev/null

export APP_KEY='base64:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s='
export APP_ENV=production
export APP_DEBUG=false
export APP_URL='https://gateway.example.test'

(
  cd "$root"
  php artisan --version
  php artisan route:list --no-ansi >/dev/null

  rm -f bootstrap/cache/packages.php bootstrap/cache/services.php
  php artisan package:discover --ansi >/dev/null
  [[ -f bootstrap/cache/packages.php && -f bootstrap/cache/services.php ]]
  php artisan route:list --no-ansi >/dev/null

  php -r '
  require "vendor/autoload.php";
  foreach (["laravel/framework", "mcp/sdk", "league/oauth2-server"] as $package) {
      if (\Composer\InstalledVersions::getPrettyVersion($package) === null) {
          fwrite(STDERR, "Missing Composer runtime identity: {$package}\n");
          exit(1);
      }
  }
  $checks = \App\Support\SimpleWebInstaller::preflight(getcwd(), true);
  foreach ($checks as $name => $passed) {
      if (! $passed) {
          fwrite(STDERR, "Installer preflight failed in packaged tree: {$name}\n");
          exit(1);
      }
  }
  '

  sqlite="$tmp/package-migration-smoke.sqlite"
  : > "$sqlite"
  DB_CONNECTION=sqlite DB_DATABASE="$sqlite" CACHE_STORE=array SESSION_DRIVER=array \
    php artisan migrate --force --no-interaction >/dev/null
)

printf 'Deployment ZIP verified: %s\n' "$zip_path"
printf 'Files: %s\n' "$(find "$root" -type f | wc -l)"
printf 'Dependency license/notice files retained: %s\n' "$license_count"
