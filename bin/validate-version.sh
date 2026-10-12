#!/usr/bin/env bash
# Fail-closed version identity policy. CI candidates use prerelease names; only
# immutable, explicitly Owner-approved stable versions may be published.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: bash bin/validate-version.sh <candidate|release|package> <version>" >&2
  exit 2
fi

kind="$1"
version="$2"
stable_re='^[0-9]+\.[0-9]+\.[0-9]+$'
candidate_re='^[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$'
case "$kind" in
  candidate)
    [[ "$version" =~ $candidate_re ]] || {
      echo "Candidate packages require a distinct X.Y.Z-rc.N prerelease VERSION; never use the final X.Y.Z release version." >&2
      exit 1
    }
    ;;
  release)
    [[ "$version" =~ $stable_re ]] || {
      echo "Public releases require a stable X.Y.Z VERSION, never a prerelease candidate." >&2
      exit 1
    }
    ;;
  package)
    [[ "$version" =~ $stable_re || "$version" =~ $candidate_re ]] || {
      echo "Package VERSION must be stable X.Y.Z or prerelease X.Y.Z-rc.N." >&2
      exit 1
    }
    ;;
  *)
    echo "Unknown version policy kind: $kind" >&2
    exit 2
    ;;
esac
