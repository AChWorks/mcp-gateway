#!/usr/bin/env bash
# Always verify the v2-to-v3 rejection on a disposable *local fixture*.
# Never inspect a real installation or point this at a production DB.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_runtime="$(realpath "${1:?Usage: test-v3-major-upgrade-guard.sh <unpacked v3 runtime> <v3 update ZIP>}")"
update_zip="$(realpath "${2:?Missing v3 update ZIP}")"
[[ -d "$release_runtime/vendor" && -f "$release_runtime/VERSION" ]] || {
  echo 'Disposable v3 runtime is missing.' >&2
  exit 2
}
[[ -f "$update_zip" ]] || { echo 'V3 update ZIP missing.' >&2; exit 2; }
case "$(tr -d '[:space:]' < "$release_runtime/VERSION")" in
  3.*) ;;
  *) echo 'V3 major-version guard only applies to a v3 candidate.' >&2; exit 2 ;;
esac
fixture="$(mktemp -d "${TMPDIR:-/tmp}/gateway-v3-guard-XXXXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
cp -a "$release_runtime/." "$fixture/"
printf '2.7.3\n' > "$fixture/VERSION"
mkdir -p "$fixture/storage/app/private"
touch "$fixture/storage/app/private/installed"
cat > "$fixture/.env" <<'ENV'
APP_ENV=testing
APP_KEY=base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
ENV
(cd "$fixture" && unzip -oq "$update_zip")
FIXTURE_ROOT="$fixture" php -r '
$root = getenv("FIXTURE_ROOT");
require $root."/update/WebUpdater.php";
$updater = new \McpGatewayUpdate\WebUpdater($root, $root."/update");
try {
    $updater->inspect();
    fwrite(STDERR, "FAIL: v2 to v3 in-place update was admitted.\n");
    exit(3);
} catch (\RuntimeException $exception) {
    if (!str_contains($exception->getMessage(), "v3 requires a clean installation")) {
        fwrite(STDERR, "Unexpected updater rejection: ".$exception->getMessage()."\n");
        exit(4);
    }
    echo "PASS: major-version transition refused before mutation.\n";
}
'
[[ "$(cat "$fixture/VERSION")" == '2.7.3' ]]
[[ -f "$fixture/storage/app/private/installed" ]]
[[ ! -e "$fixture/storage/app/private/update-state.json" ]]
[[ ! -e "$fixture/storage/app/private/update-journal.json" ]]
echo 'PASS: Existing v2 VERSION, installer marker and preflight journal are unchanged.'
