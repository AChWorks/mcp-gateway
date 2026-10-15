#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

renderer="$repo_root/bin/render-github-release-notes.sh"
version="$(tr -d '[:space:]' < "$repo_root/VERSION")"

# The current candidate/stable identity must agree with tracked VERSION,
# not merely the public stable H1 boundary.
headline="$(sed -n '3p' "$repo_root/RELEASE_NOTES.md")"
if [[ "$version" == *-rc.* ]]; then
  printf -v expected '**Corrective source candidate `%s` — NOT PUBLISHED.**' "$version"
  [[ "$headline" == "$expected" ]] || {
    echo "Current release notes identity differs from VERSION $version." >&2
    exit 1
  }
else
  [[ "$headline" == "**Stable v$version"* && "$headline" != *"source candidate"* ]] || {
    echo "Stable release notes must identify v$version, not an RC." >&2
    exit 1
  }
fi

# The tracked VERSION can be a candidate, but GitHub's public Release
# renderer is explicitly stable-only. Validate planned stable notes now
# without turning this prerelease into a public Release identity.
bash "$repo_root/bin/validate-version.sh" package "$version"
stable_version="${version%%-rc.*}"
bash "$repo_root/bin/validate-version.sh" release "$stable_version"
bash "$renderer" "$stable_version" "$repo_root/RELEASE_NOTES.md" "$temp/current.md"
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

# Never render prerelease candidate notes as a public stable Release.
if bash "$renderer" 9.9.9-rc.1 "$temp/fixture.md" "$temp/invalid-rc.md" >/dev/null 2>&1; then
  echo "Renderer accepted a prerelease identity as a public stable Release." >&2
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
