#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

renderer="$repo_root/bin/render-github-release-notes.sh"
version="$(tr -d '[:space:]' < "$repo_root/VERSION")"

# Test the actual tracked changelog and current release identity.
bash "$renderer" "$version" "$repo_root/RELEASE_NOTES.md" "$temp/current.md"
[[ -s "$temp/current.md" ]]
if grep -q '^# ' "$temp/current.md"; then
  echo "Rendered release body contains an H1/version heading." >&2
  exit 1
fi

cat > "$temp/fixture.md" <<'EOF_NOTES'
# MCP Gateway v9.9.9

**Current release.**

## Changes
- Improvement

# MCP Gateway v9.9.8

**Historical release.**
EOF_NOTES

bash "$renderer" 9.9.9 "$temp/fixture.md" "$temp/rendered.md"
grep -Fxq '**Current release.**' "$temp/rendered.md"
grep -Fxq '## Changes' "$temp/rendered.md"
if grep -Eq '^# |Historical release' "$temp/rendered.md"; then
  echo "Rendered body repeated a release heading or leaked past versions." >&2
  exit 1
fi

# Never select a historical version silently or publish a blank section.
if bash "$renderer" 9.9.8 "$temp/fixture.md" "$temp/invalid.md" >/dev/null 2>&1; then
  echo "Renderer accepted a stale changelog version." >&2
  exit 1
fi
cat > "$temp/empty.md" <<'EOF_EMPTY'
# MCP Gateway v9.9.9

# MCP Gateway v9.9.8
Old release.
EOF_EMPTY
if bash "$renderer" 9.9.9 "$temp/empty.md" "$temp/empty-output.md" >/dev/null 2>&1; then
  echo "Renderer accepted an empty current release section." >&2
  exit 1
fi

echo "GitHub release note title/deduplication and current-version boundaries verified."
