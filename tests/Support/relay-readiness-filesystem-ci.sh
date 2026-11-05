#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted disposable runner only: never invoke on Gateway/Iran hosts.
test "${GITHUB_ACTIONS:-}" = true || {
    echo 'This real-UID filesystem fixture runs only on disposable GitHub Actions.' >&2
    exit 2
}
php_bin="$(command -v php)"
reader_uid="$(id -u)"
test "$reader_uid" -gt 0 || { echo 'Expected an unprivileged GitHub runner user' >&2; exit 2; }
fixture='tests/Support/relay-readiness-filesystem.php'
root="$(sudo mktemp -d /run/mcp-relay-readiness-test-XXXXXXXX)"
trap 'sudo rm -rf -- "$root"' EXIT
sudo chmod 0755 "$root"
sudo "$php_bin" "$fixture" init "$root" "$reader_uid"

check() {
    local mutation="$1" expected="$2"
    sudo "$php_bin" "$fixture" mutate "$root" "$mutation"
    "$php_bin" "$fixture" check "$root" "$expected"
}
check missing ready
check directory-0700 blocked
check deletion-0700 blocked
check deletion-0755 blocked
check rotate-valid ready
check rotate-stale blocked
check corrupt blocked
check symlink blocked
check base-0700 blocked
check retired blocked
check missing ready
printf 'RELAY_READINESS_REAL_FS_PASS\n'
