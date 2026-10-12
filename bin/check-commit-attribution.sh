#!/usr/bin/env bash
# Check only commits introduced by a proposed PR or new main push.
# This is a project attribution policy, not cryptographic proof of identity.
set -euo pipefail

if (( $# != 2 )); then
    echo 'Usage: check-commit-attribution.sh <base-sha> <head-sha>' >&2
    exit 2
fi

base=$1
head=$2
for sha in "$base" "$head"; do
    if ! [[ $sha =~ ^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$ ]] ||
        ! git cat-file -e "${sha}^{commit}" 2>/dev/null; then
        echo "Commit attribution check: invalid or unavailable commit SHA: $sha" >&2
        exit 2
    fi
done

if ! git merge-base "$base" "$head" >/dev/null; then
    echo 'Commit attribution check: no common base; refusing an unbounded history scan.' >&2
    exit 2
fi

commits=$(git rev-list "${base}..${head}")
if [[ -z $commits ]]; then
    echo 'Commit attribution check: no new commits in range.'
    exit 0
fi

# Current owner-operated source policy. Do not use GitHub profile/contributor
# labels as authorization: Git author/committer fields are user-controlled.
owner_name='ACh'
owner_email='58507994+ach1992@users.noreply.github.com'
checked=0
rejected=0
while IFS= read -r sha; do
    identity=$(git show -s --format='%an%x1f%ae%x1f%cn%x1f%ce' "$sha")
    IFS=$'\x1f' read -r author_name author_email committer_name committer_email <<< "$identity"
    ((checked += 1))

    if [[ $author_name != "$owner_name" || $author_email != "$owner_email" ]]; then
        printf '::error::Commit %s uses an unapproved Git author: %q\n' \
            "$sha" "$author_name <$author_email>" >&2
        ((rejected += 1))
    fi

    # GitHub's signed web merges are created on behalf of the owner.
    if ! { [[ $committer_name == "$owner_name" && $committer_email == "$owner_email" ]] ||
           [[ $committer_name == 'GitHub' && $committer_email == 'noreply@github.com' ]]; }; then
        printf '::error::Commit %s uses an unapproved Git committer: %q\n' \
            "$sha" "$committer_name <$committer_email>" >&2
        ((rejected += 1))
    fi
done <<< "$commits"

if (( rejected > 0 )); then
    printf 'Commit attribution: FAILED; %d metadata violations across %d new commits.\n' \
        "$rejected" "$checked" >&2
    echo 'Set the correct Git author AND committer before making new commits; do not rewrite already merged history.' >&2
    exit 1
fi
printf 'Commit attribution: PASS; %d new commits checked.\n' "$checked"
