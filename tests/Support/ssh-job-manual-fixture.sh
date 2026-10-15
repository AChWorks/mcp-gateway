#!/usr/bin/env bash
# Isolated root-only manual fixture. Not wired to default CI or production.
set -Eeuo pipefail
if [[ "$(id -u)" != 0 || "$(cat /proc/1/comm)" != systemd ]]; then
    echo "Requires explicit disposable systemd test host root context." >&2
    exit 2
fi
worktree="${MGW_SOURCE_WORKTREE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)}"
base="$(mktemp -d /srv/ai-workspace/mgw-job-fixture-XXXXXX)"
suffix="${base##*-}"
user="mgwfx${suffix,,}"
port=46352
has_account=false
linger_enabled=false
daemon_started=false
cleanup() {
    local code=$?
    trap - EXIT
    if [[ "$daemon_started" == true && -f "$base/sshd.pid" ]]; then
        local pid
        pid="$(cat "$base/sshd.pid" 2>/dev/null || true)"
        if [[ "$pid" =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -Fq "$base/sshd.conf"; then
            kill "$pid" 2>/dev/null || true
        fi
    fi
    if [[ "$linger_enabled" == true ]]; then
        loginctl disable-linger "$user" >/dev/null 2>&1 || true
        loginctl terminate-user "$user" >/dev/null 2>&1 || true
    fi
    if [[ "$has_account" == true ]]; then
        local uid
        uid="$(id -u "$user" 2>/dev/null || true)"
        if [[ "$uid" =~ ^[0-9]+$ ]]; then
            for directory in /var/tmp/.mcp-gateway-job-*; do
                [[ -d "$directory" && ! -L "$directory" ]] || continue
                [[ "$(stat -c '%u' "$directory")" == "$uid" ]] || continue
                [[ "$(stat -c '%a' "$directory")" == 700 ]] || continue
                for name in script.sh wrapper.sh stdout stderr exit-code; do
                    rm -f -- "$directory/$name"
                done
                rmdir -- "$directory" 2>/dev/null || true
            done
        fi
        userdel -r "$user" >/dev/null 2>&1 || true
    fi
    if [[ "$base" == /srv/ai-workspace/mgw-job-fixture-* && -d "$base" && ! -L "$base" ]]; then
        rm -f -- "$base"/host_ed25519* "$base"/login_rsa* "$base"/sshd.conf "$base"/sshd.log "$base"/sshd.pid
        rmdir -- "$base" 2>/dev/null || true
    fi
    exit "$code"
}
trap cleanup EXIT
if id "$user" >/dev/null 2>&1 || ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "Fixture account or port already in use; refuse." >&2
    exit 1
fi
mkdir -p /run/sshd
useradd -m -s /bin/bash "$user"
has_account=true
install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
ssh-keygen -q -t ed25519 -N '' -f "$base/host_ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$base/login_rsa"
awk '{print $1" "$2}' "$base/host_ed25519.pub" > "$base/host_ed25519.pin"
install -m 600 -o "$user" -g "$user" "$base/login_rsa.pub" "/home/$user/.ssh/authorized_keys"
chown aiworker:aiworker "$base" "$base/login_rsa" "$base/login_rsa.pub" "$base/host_ed25519.pin"
chmod 700 "$base"
chmod 600 "$base/login_rsa"
loginctl enable-linger "$user"
linger_enabled=true
sleep 2
test "$(loginctl show-user "$user" -p Linger --value)" = yes
cat > "$base/sshd.conf" <<EOF
Port $port
ListenAddress 127.0.0.1
PidFile $base/sshd.pid
HostKey $base/host_ed25519
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
AllowUsers $user
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
X11Forwarding no
Subsystem sftp internal-sftp
LogLevel ERROR
EOF
/usr/sbin/sshd -t -f "$base/sshd.conf"
/usr/sbin/sshd -f "$base/sshd.conf" -E "$base/sshd.log"
daemon_started=true
for _ in {1..30}; do
    if ss -ltn "( sport = :$port )" | grep -q LISTEN; then break; fi
    sleep 0.1
done
ss -ltn "( sport = :$port )" | grep -q LISTEN
uid="$(id -u "$user")"
runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    systemctl --user show-environment >/dev/null
echo "Running real disposable SSH/systemd Job acceptance"
runuser -u aiworker -- env \
    SSH_JOB_FIXTURE_ENABLED=1 \
    SSH_JOB_FIXTURE_PORT="$port" \
    SSH_JOB_FIXTURE_USER="$user" \
    SSH_JOB_FIXTURE_HOST_KEY="$base/host_ed25519.pin" \
    SSH_JOB_FIXTURE_PRIVATE_KEY="$base/login_rsa" \
    /bin/bash -c 'cd "$1" && php artisan test --compact tests/Feature/Mcp/SshJobFixtureTest.php' _ "$worktree"
echo "Disabling linger, then verifying unsupported-host detection"
loginctl disable-linger "$user"
runuser -u aiworker -- env \
    SSH_JOB_FIXTURE_ENABLED=1 \
    SSH_JOB_FIXTURE_NO_LINGER=1 \
    SSH_JOB_FIXTURE_PORT="$port" \
    SSH_JOB_FIXTURE_USER="$user" \
    SSH_JOB_FIXTURE_HOST_KEY="$base/host_ed25519.pin" \
    SSH_JOB_FIXTURE_PRIVATE_KEY="$base/login_rsa" \
    /bin/bash -c 'cd "$1" && php artisan test --compact tests/Feature/Mcp/SshJobFixtureTest.php --filter=test_real_host_without_linger_refuses_detached_execution_before_script_staging' _ "$worktree"
echo "Fixture passed; cleaning temporary SSH account and listener."
