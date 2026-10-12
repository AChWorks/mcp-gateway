#!/usr/bin/env bash
# Version identities must be stable for public Releases and distinct prerelease
# candidates, while remaining compatible with the existing WebUpdater path.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
policy="$root/bin/validate-version.sh"

for version in 2.1.2-rc.1 2.1.2-rc.2 2.1.2-rc.10; do
  bash "$policy" candidate "$version"
  bash "$policy" package "$version"
  if bash "$policy" release "$version" >/dev/null 2>&1; then
    echo "Public Release accepted prerelease $version." >&2
    exit 1
  fi
done

for version in 2.0.3 2.1.1 2.1.2; do
  bash "$policy" release "$version"
  bash "$policy" package "$version"
  if bash "$policy" candidate "$version" >/dev/null 2>&1; then
    echo "Candidate accepted final stable version $version." >&2
    exit 1
  fi
done

for version in 2.1.2-rc.0 2.1.2-rc.01 2.1.2-rc.alpha 2.1.2-beta.1 2.1.2-rc.1+changed '2.1.2/../../' ''; do
  if bash "$policy" package "$version" >/dev/null 2>&1; then
    echo "Malformed version passed package policy: $version." >&2
    exit 1
  fi
done

php -r '
require $argv[1];
$reader = (new ReflectionClass(McpGatewayUpdate\WebUpdater::class))->getMethod("readVersion");
$updater = new McpGatewayUpdate\WebUpdater(sys_get_temp_dir(), sys_get_temp_dir());
$file = tempnam(sys_get_temp_dir(), "gateway-version-");
if (!is_string($file)) { throw new RuntimeException("Could not create test fixture."); }
try {
  foreach (["2.1.1", "2.1.2-rc.1", "2.1.2-rc.2", "2.1.2"] as $version) {
    file_put_contents($file, $version."\n");
    if ($reader->invoke($updater, $file, "Fixture") !== $version) {
      throw new RuntimeException("WebUpdater rejected a supported version.");
    }
  }
  foreach (["2.1.2-rc.0", "2.1.2-rc.01", "2.1.2-beta.1", "2.1.2-rc.1+changed"] as $invalid) {
    file_put_contents($file, $invalid."\n");
    try { $reader->invoke($updater, $file, "Fixture"); }
    catch (RuntimeException) { continue; }
    throw new RuntimeException("WebUpdater accepted an invalid prerelease version.");
  }
  $order = ["2.1.1", "2.1.2-rc.1", "2.1.2-rc.2", "2.1.2-rc.10", "2.1.2"];
  foreach (array_slice($order, 0, -1) as $i => $lower) {
    if (!version_compare($lower, $order[$i+1], "<")) {
      throw new RuntimeException("Updater version comparison is not monotonic.");
    }
  }
} finally { @unlink($file); }
' "$root/bin/mcp-gateway-web-updater.php"

# Reusing an rc number for a changed head reproduces the operator's original
# same-version update rejection. Test the actual distribution-identity guard.
fixture="$(mktemp)"
trap 'rm -f "$fixture"' EXIT
sha="0123456789abcdef0123456789abcdef01234567"
echo "mcp-gateway-v2.1.2-rc.1-candidate-$sha" > "$fixture"
bash "$root/bin/check-candidate-artifact-reuse.sh" 2.1.2-rc.1 "$sha" "$fixture" >/dev/null
if bash "$root/bin/check-candidate-artifact-reuse.sh" 2.1.2-rc.1 1111111111111111111111111111111111111111 "$fixture" >/dev/null 2>&1; then
  echo 'Candidate reuse across different HEADs was not blocked.' >&2
  exit 1
fi
bash "$root/bin/check-candidate-artifact-reuse.sh" 2.1.2-rc.2 1111111111111111111111111111111111111111 "$fixture" >/dev/null

bash "$policy" package "$(tr -d '[:space:]' < "$root/VERSION")"
echo 'PASS candidate/stable release separation, updater parsing, reuse rejection, and monotonic upgrade order.'
