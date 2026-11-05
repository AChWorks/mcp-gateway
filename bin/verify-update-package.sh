#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: bash bin/verify-update-package.sh <zip-path>" >&2
  exit 2
fi

zip_path="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$zip_path" ]] || { echo "Update ZIP does not exist: $zip_path" >&2; exit 1; }

for command in unzip php find sort diff awk grep mktemp sha256sum basename dirname stat; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required verification command is unavailable: $command" >&2; exit 1; }
done

checksum_path="$zip_path.sha256"
[[ -f "$checksum_path" ]] || { echo "Update ZIP checksum does not exist: $checksum_path" >&2; exit 1; }

zip_dir="$(cd "$(dirname "$zip_path")" && pwd -P)"
zip_name="$(basename "$zip_path")"
checksum_name="$(basename "$checksum_path")"
expected_checksum="$(sha256sum "$zip_path" | awk -v name="$zip_name" '{print $1 "  " name}')"
actual_checksum="$(cat "$checksum_path")"
[[ "$actual_checksum" == "$expected_checksum" ]] || {
  echo "Update ZIP checksum file must contain the ZIP basename and exact SHA-256 digest." >&2
  exit 1
}
(
  cd "$zip_dir"
  sha256sum --check --strict "$checksum_name" >/dev/null
)

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
[[ -f "$root/update/Recover.php" ]] || { echo "Private recovery CLI is missing." >&2; exit 1; }
[[ -f "$root/update/UPDATE_VERSION" ]] || { echo "UPDATE_VERSION is missing." >&2; exit 1; }
[[ -f "$root/update/PUBLIC_ENTRY_SHA256" ]] || { echo "PUBLIC_ENTRY_SHA256 is missing." >&2; exit 1; }
[[ -f "$root/update/MANAGED_PUBLIC_PATHS" ]] || { echo "MANAGED_PUBLIC_PATHS is missing." >&2; exit 1; }
[[ -f "$root/update/manifest.sha256" ]] || { echo "Update manifest is missing." >&2; exit 1; }

php -l "$root/update/WebUpdater.php" >/dev/null
php -l "$root/update/Recover.php" >/dev/null
# OpenLiteSpeed itself must traverse the public update directory and read its
# entry point even when the LSAPI worker owns the application code.
[[ "$(stat -c '%a' "$root/public/update")" == '755'     && "$(stat -c '%a' "$root/public/update/index.php")" == '644' ]] || {
  echo "Public browser-updater permissions are not portable: require 0755 directory and 0644 entry, without changing private staging." >&2
  exit 1
}
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

if grep -n '^$' "$root/update/MANAGED_PUBLIC_PATHS" >/dev/null \
  || grep -Ev '^[A-Za-z0-9._/-]+$' "$root/update/MANAGED_PUBLIC_PATHS" | grep . >/dev/null \
  || grep -E '(^|/)\.\.(/|$)|^/|\\|/$|^update($|/)' "$root/update/MANAGED_PUBLIC_PATHS" >/dev/null; then
  echo "MANAGED_PUBLIC_PATHS contains an unsafe path." >&2
  exit 1
fi
if [[ "$(sort "$root/update/MANAGED_PUBLIC_PATHS" | uniq -d | wc -l)" -ne 0 ]]; then
  echo "MANAGED_PUBLIC_PATHS contains a duplicate path." >&2
  exit 1
fi
diff -u "$repo_root/bin/update-managed-public-paths.txt" "$root/update/MANAGED_PUBLIC_PATHS"
while IFS= read -r public_file; do
  [[ -n "$public_file" ]] || continue
  grep -Fx "$public_file" "$root/update/MANAGED_PUBLIC_PATHS" >/dev/null || {
    echo "Public payload file is outside the Gateway-owned manifest: public/$public_file" >&2
    exit 1
  }
done < <(find "$root/update/payload/public" -type f -printf '%P\n' | LC_ALL=C sort)

version="$(tr -d '[:space:]' < "$root/update/UPDATE_VERSION")"
payload_version="$(tr -d '[:space:]' < "$root/update/payload/VERSION")"
repo_version="$(tr -d '[:space:]' < "$repo_root/VERSION")"
bash "$repo_root/bin/validate-version.sh" package "$version"
[[ "$version" == "$payload_version" && "$version" == "$repo_version" ]] || { echo "Update/repository/payload versions do not match." >&2; exit 1; }

cat > "$tmp/expected-payload-top.txt" <<'EOF_PAYLOAD'
.env.example
LICENSE
VERSION
app
artisan
bin
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

# The Browser Update must ship exactly the two signed-off host scripts, not
# development tooling. Validate both payload identity and pinned release SHA.
bin_dir="$root/update/payload/bin"
[[ -d "$bin_dir" && ! -L "$bin_dir" ]] || { echo "Update payload bin/ is missing or unsafe." >&2; exit 1; }
for script in managed-reverse-target.sh managed-reverse-gateway.sh; do
  [[ -f "$bin_dir/$script" && ! -L "$bin_dir/$script" ]] || { echo "Update payload is missing approved host script: $script" >&2; exit 1; }
  bash -n "$bin_dir/$script"
done
[[ "$(find "$bin_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" == "$(printf '%s\n' managed-reverse-gateway.sh managed-reverse-target.sh)" ]] || {
  echo "Update payload contains unexpected bin/ content." >&2; exit 1;
}
php -r '
$cfg=file_get_contents($argv[1]);
foreach (["installer_sha256"=>"managed-reverse-target.sh", "gateway_script_sha256"=>"managed-reverse-gateway.sh"] as $setting=>$file) {
  if (!preg_match("/\x27".preg_quote($setting, "/")."\x27\s*=>\s*\x27([a-f0-9]{64})\x27/", $cfg, $m)
      || !hash_equals($m[1], hash_file("sha256", $argv[2]."/".$file))) {
    fwrite(STDERR, "Managed Reverse SSH script does not match the release-pinned digest: ".$file."\n");
    exit(1);
  }
}
' "$root/update/payload/config/ssh.php" "$bin_dir"

# The Relay host helper is packaged under resources/ rather than widening
# the privileged updater-managed bin/ leaf allowlist.
relay_script="$root/update/payload/resources/host/connection-relay-gateway.py"
relay_pin="$root/update/payload/config/connection_relays.php"
[[ -f "$relay_script" && ! -L "$relay_script" && -f "$relay_pin" && ! -L "$relay_pin" ]] || {
  echo "Update payload is missing the Relay host helper or its release digest." >&2; exit 1
}
python3 - "$relay_script" <<'PYCODE'
import ast, pathlib, sys
ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding='utf8'))
PYCODE
php -r '
$cfg = include $argv[1];
$expected = $cfg["gateway_retirement_helper_sha256"] ?? null;
$actual = hash_file("sha256", $argv[2]);
if (!is_string($expected) || !preg_match("/^[a-f0-9]{64}$/D", $expected) || !hash_equals($expected, $actual)) {
    fwrite(STDERR, "Update Relay host helper has mismatched release-pinned digest.\n");
    exit(1);
}
' "$relay_pin" "$relay_script"

[[ ! -e "$root/update/payload/.env" ]] || { echo "Update payload must not contain .env." >&2; exit 1; }
[[ ! -e "$root/update/payload/storage" ]] || { echo "Update payload must not contain storage." >&2; exit 1; }
[[ -f "$root/update/payload/vendor/autoload.php" ]] || { echo "Update payload is missing vendor/autoload.php." >&2; exit 1; }
[[ ! -e "$root/update/payload/composer.lock" ]] || { echo "Update payload must not contain source composer.lock." >&2; exit 1; }
[[ ! -e "$root/update/payload/vendor/bin" ]] || { echo "Update payload must not contain vendor/bin." >&2; exit 1; }

php "$repo_root/bin/prune-production-vendor.php" --check "$root/update/payload/vendor"

printf 'Browser update ZIP verified: %s\n' "$zip_path"
printf 'Version: %s\n' "$version"
printf 'Files: %s\n' "$(find "$root/update" "$root/public/update" -type f | wc -l)"
