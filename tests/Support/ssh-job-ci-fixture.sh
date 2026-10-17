#!/usr/bin/env bash
# A real systemd-user SSH Job acceptance test on a disposable GitHub runner.
# Reuses the established loopback-only tests/Support/ssh-fixture.sh account.
# Never run on an operator/prod host or against a non-fixture SSH target.
set -Eeuo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'GitHub-hosted disposable runner required.' >&2; exit 2; }
[[ "$(cat /proc/1/comm)" == systemd ]] || { echo 'systemd PID 1 required.' >&2; exit 2; }
[[ "${SSH_FIXTURE_USER:-}" =~ ^mcpfx[0-9]+$ ]] || { echo 'Unexpected SSH fixture account.' >&2; exit 2; }
[[ "${SSH_FIXTURE_PORT_MODERN:-}" == 46231 ]] || { echo 'Unexpected fixture port.' >&2; exit 2; }
[[ -f "${SSH_FIXTURE_RSA_LOGIN_KEY:-/nonexistent}" ]] || { echo 'Missing existing fixture key.' >&2; exit 2; }

user="$SSH_FIXTURE_USER"
cleanup() {
  sudo loginctl disable-linger "$user" >/dev/null 2>&1 || true
  sudo loginctl terminate-user "$user" >/dev/null 2>&1 || true
}
trap cleanup EXIT

export SSH_JOB_FIXTURE_ENABLED=1
export SSH_JOB_FIXTURE_PORT="$SSH_FIXTURE_PORT_MODERN"
export SSH_JOB_FIXTURE_USER="$user"
export SSH_JOB_FIXTURE_HOST_KEY="$SSH_FIXTURE_ED25519_HOST_PUB"
export SSH_JOB_FIXTURE_PRIVATE_KEY="$SSH_FIXTURE_RSA_LOGIN_KEY"
export SSH_JOB_FIXTURE_PASSPHRASE="$SSH_FIXTURE_KEY_PASSPHRASE"

sudo loginctl enable-linger "$user"
uid="$(id -u "$user")"
for _ in {1..30}; do
  if sudo runuser -u "$user" -- env \
      XDG_RUNTIME_DIR="/run/user/$uid" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
      systemctl --user show-environment >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
sudo runuser -u "$user" -- env \
  XDG_RUNTIME_DIR="/run/user/$uid" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
  systemctl --user show-environment >/dev/null

php artisan test --compact tests/Feature/Mcp/SshJobFixtureTest.php \
  --filter=test_job_longer_than_http_budget_has_bounded_output_durable_exit_and_verified_cancel

# Regression: no systemd-wide file-size cap may prevent a legitimate >1 MiB
# child write; oversized stdout/stderr alone must stay bounded and harmless.
php artisan test --compact tests/Feature/Mcp/SshJobFixtureTest.php \
  --filter=test_job_can_write_large_regular_files_while_capturing_bounded_stdout_and_stderr

sudo loginctl disable-linger "$user"
# The guard must reject new detached work while the user manager may linger
# briefly from its last session; don't assume the bus vanishes immediately.
export SSH_JOB_FIXTURE_NO_LINGER=1
php artisan test --compact tests/Feature/Mcp/SshJobFixtureTest.php \
  --filter=test_real_host_without_linger_refuses_detached_execution_before_script_staging
