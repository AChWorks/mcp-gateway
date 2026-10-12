#!/usr/bin/env bash
# A candidate VERSION that has already been distributed under another PR HEAD
# must never be reused for a new package. GitHub Actions artifacts are the
# authoritative short-lived distribution register. This fails closed on API
# errors; long-term uniqueness still requires incrementing rc.N every round.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <candidate-version> <PR-HEAD-SHA> [test-only-artifact-names-file]" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$root/bin/validate-version.sh" candidate "$1"
version="$1"
head="$2"

if [[ ! "$head" =~ ^[a-f0-9]{40}$ ]]; then
  echo "Exact candidate HEAD must be a full SHA." >&2
  exit 2
fi

prefix="mcp-gateway-v${version}-candidate-"
expected="${prefix}${head}"
if [[ $# -eq 3 ]]; then
  [[ -f "$3" && -r "$3" ]] || { echo "Fixture names file cannot be read." >&2; exit 2; }
  existing="$(cat -- "$3")"
else
  : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must identify the authorized repository}"
  [[ "$GITHUB_REPOSITORY" == "AChWorks/mcp-gateway" ]] || {
    echo "Unexpected repository identity; refusing candidate publication." >&2
    exit 2
  }
  # GitHub's artifact API is paginated; check every retained candidate,
  # not just the first 100. GH_TOKEN requires read-only actions permission.
  existing="$(gh api --paginate --method GET \
    "repos/$GITHUB_REPOSITORY/actions/artifacts?per_page=100" \
    --jq '.artifacts[].name')"
fi

while IFS= read -r name; do
  [[ -n "$name" ]] || continue
  if [[ "$name" == "$prefix"* && "$name" != "$expected" ]]; then
    echo "VERSION $version already has a distributed candidate for another HEAD: $name" >&2
    echo "Increment -rc.N before producing a new operator-test ZIP." >&2
    exit 1
  fi
done <<< "$existing"

echo "Candidate VERSION $version has no conflicting retained artifact."
