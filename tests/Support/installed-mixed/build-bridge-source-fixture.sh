#!/usr/bin/env bash
# Test-only reproducible ZIP from a READ_ONLY exact WP AI Bridge source commit.
# Never install or mutate the Bridge checkout. This is not a public release.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <read-only-wp-ai-bridge-git-repo> <output-zip>" >&2
  exit 2
fi
repo="$1"
output="$2"
commit=c522ae99bd11926eb74c007d187354013202fc4c
[[ "$(git -C "$repo" cat-file -t "$commit")" == commit ]] || exit 2
epoch="$(git -C "$repo" show -s --format=%ct "$commit")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/source" "$tmp/stage/wp-ai-bridge"
git -C "$repo" archive --format=tar "$commit" | tar -xf - -C "$tmp/source"
for file in wp-ai-bridge.php uninstall.php README.md CHANGELOG.md LICENSE; do
  cp "$tmp/source/$file" "$tmp/stage/wp-ai-bridge/"
done
cp -R "$tmp/source/src" "$tmp/source/languages" "$tmp/stage/wp-ai-bridge/"
# Stable hash regardless of the build host's current clock or source checkout.
find "$tmp/stage" -exec touch -h -d "@$epoch" {} +
mkdir -p "$(dirname "$output")"
output="$(cd "$(dirname "$output")" && pwd -P)/$(basename "$output")"
[[ ! -e "$output" ]] || { echo "Refusing to overwrite a pinned fixture." >&2; exit 2; }
(cd "$tmp/stage"; find wp-ai-bridge -type f | LC_ALL=C sort | TZ=UTC zip -X -q "$output" -@)
unzip -tq "$output"
sha256sum "$output"
