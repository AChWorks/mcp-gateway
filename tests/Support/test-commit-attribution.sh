#!/usr/bin/env bash
# Hermetic checks for the attribution guard. No remote or existing repo mutation.
set -euo pipefail

source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
check="$source_dir/bin/check-commit-attribution.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/git"
git init -q -b main "$repo"
cd "$repo"

commit_as() {
    local author_name=$1 author_email=$2 committer_name=$3 committer_email=$4 title=$5
    GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email" \
        GIT_COMMITTER_NAME="$committer_name" GIT_COMMITTER_EMAIL="$committer_email" \
        git -c commit.gpgsign=false commit --quiet --allow-empty -m "$title"
    git rev-parse HEAD
}

expect_pass() {
    local title=$1 base=$2 head=$3
    if ! bash "$check" "$base" "$head" >/dev/null 2>&1; then
        echo "FAIL (unexpected rejection): $title" >&2
        bash "$check" "$base" "$head" >&2 || true
        exit 1
    fi
    echo "PASS: $title"
}
expect_fail() {
    local title=$1 base=$2 head=$3
    if bash "$check" "$base" "$head" >/dev/null 2>&1; then
        echo "FAIL (unexpected acceptance): $title" >&2
        exit 1
    fi
    echo "PASS: $title"
}

owner='58507994+ach1992@users.noreply.github.com'
foreign='ai-development@users.noreply.github.com'
base=$(commit_as ACh "$owner" ACh "$owner" 'base')
good=$(commit_as ACh "$owner" ACh "$owner" 'normal owner commit')
expect_pass 'owner identity' "$base" "$good"
expect_pass 'empty range' "$good" "$good"

web_merge=$(commit_as ACh "$owner" GitHub 'noreply@github.com' 'web merge')
expect_pass 'signed-web-merge committer metadata' "$good" "$web_merge"

# Use isolated branches from the same base so bad fixtures do not pollute main.
git switch -q -c wrong-author-email "$base"
bad_email=$(commit_as 'AChWorks AI Developer' "$foreign" 'AChWorks AI Developer' "$foreign" 'foreign author')
expect_fail 'historical wrong author+committer is rejected' "$base" "$bad_email"

# New good work based on a bad historical commit should not rescan the past.
good_after_bad=$(commit_as ACh "$owner" ACh "$owner" 'good after historical identity')
expect_pass 'already-integrated bad author outside range is not scanned' "$bad_email" "$good_after_bad"
expect_fail 'bad ancestor within proposed range is scanned' "$base" "$good_after_bad"

git switch -q -c wrong-name "$base"
bad_name=$(commit_as 'Someone Else' "$owner" ACh "$owner" 'wrong author name')
expect_fail 'wrong author name even with owner email' "$base" "$bad_name"

git switch -q -c wrong-committer "$base"
bad_committer=$(commit_as ACh "$owner" GitHub 'wrong@example.com' 'wrong committer email')
expect_fail 'unexpected committer is rejected' "$base" "$bad_committer"
expect_fail 'invalid SHA rejected' "$base" 'not-a-sha'

echo 'All attribution fixture tests passed.'
