#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: bash bin/render-github-release-notes.sh <version> <release-notes-source> <output>" >&2
  exit 2
fi

version="$1"
source="$2"
output="$3"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release version: $version" >&2; exit 2; }
[[ -f "$source" && -r "$source" ]] || { echo "Release notes source is not readable: $source" >&2; exit 1; }
[[ "$source" != "$output" ]] || { echo "Output must not overwrite source release notes." >&2; exit 2; }

# The changelog keeps version headings. GitHub displays the release name itself;
# its published body must contain only the current version's section, without H1.
expected="# MCP Gateway v$version"
actual="$(head -n 1 "$source")"
[[ "$actual" == "$expected" ]] || {
  echo "Release notes must start with the exact version heading: $expected" >&2
  exit 1
}

temp="$(mktemp)"
trap 'rm -f "$temp"' EXIT
awk '
  NR == 1 { next }
  /^# / { exit }
  { print }
' "$source" > "$temp"

grep -q '[^[:space:]]' "$temp" || {
  echo "Current release notes section is empty: $version" >&2
  exit 1
}

cp -- "$temp" "$output"
