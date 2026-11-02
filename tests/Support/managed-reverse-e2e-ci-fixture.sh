#!/usr/bin/env bash
# Exact generated one-command onboarding on a disposable GitHub-hosted
# systemd runner. Not suitable for a live Gateway or an operator server.
set -Eeuo pipefail
umask 077
export LC_ALL=C

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ "${GITHUB_ACTIONS:-}" == true && "$EUID" -ne 0 ]] ||
    die "Only the normal, non-root user on disposable GitHub Actions may invoke this fixture."
[[ "$(cat /proc/1/comm)" == systemd ]] || die "Real systemd PID 1 required."
for tool in sudo sshd ssh-keygen ssh-keyscan socat openssl curl php python3 systemctl; do
    command -v "$tool" >/dev/null 2>&1 || die "Missing expected disposable runner tool: $tool."
done
[[ ! -e /etc/mcp-gateway-reverse && ! -e /var/lib/mcp-gateway-reverse ]] ||
    die "Fixture requires a clean disposable runner with no prior managed SSH state."
[[ ! -e /etc/systemd/system/mcp-gateway-reverse-sshd.service ]] ||
    die "Unrelated Gateway SSHD service must not be touched."
if compgen -G '/etc/systemd/system/mcp-gateway-reverse-*.service' >/dev/null; then
    die "Unrelated managed Target services must not be touched."
fi
getent passwd deploy.prod >/dev/null && die "Fixture test account already exists."
getent passwd mcp-reverse >/dev/null && die "Gateway control account already exists."

tmp="$(mktemp -d /tmp/mcp-managed-e2e.XXXXXXXX)"
control_port=45770
target_port=45691
app_port=44801
tls_port=44999
target_id="ci-managed-reverse"
target_unit=""
control_user=""
prior_unit=""
prior_user=""
php_pid=""
tls_pid=""
export MANAGED_REVERSE_E2E_DIR="$tmp"
export MANAGED_REVERSE_TARGET_PORT="$target_port"
export MANAGED_REVERSE_CONTROL_PORT="$control_port"
export APP_URL="https://127.0.0.1:$tls_port"
export APP_ENV=local APP_DEBUG=false DB_CONNECTION=sqlite
export DB_DATABASE="$tmp/gateway.sqlite" SESSION_DRIVER=file
export CACHE_STORE=array QUEUE_CONNECTION=sync SSH_REVERSE_APPROVED_ROUTES='{}'
export APP_KEY="base64:$(openssl rand -base64 32 | tr -d '\n')"

cleanup() {
    [[ -z "$php_pid" ]] || { kill "$php_pid" >/dev/null 2>&1 || true; wait "$php_pid" 2>/dev/null || true; }
    [[ -z "$tls_pid" ]] || { kill "$tls_pid" >/dev/null 2>&1 || true; wait "$tls_pid" 2>/dev/null || true; }
    local owned_unit
    for owned_unit in "$target_unit" "$prior_unit"; do
        if [[ -n "$owned_unit" && "$owned_unit" =~ ^mcp-gateway-reverse-[0-9a-hjkmnp-tv-z]{26}\.service$ ]]; then
            sudo systemctl disable --now "$owned_unit" >/dev/null 2>&1 || true
            sudo rm -f -- "/etc/systemd/system/$owned_unit"
        fi
    done
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ -f "$tmp/target.pid" ]]; then
        local pid
        pid="$(cat "$tmp/target.pid")"
        [[ "$pid" =~ ^[0-9]+$ ]] && sudo kill "$pid" 2>/dev/null || true
    fi
    local owned_account
    for owned_account in "$control_user" "$prior_user"; do
        if [[ -n "$owned_account" && "$owned_account" =~ ^mcp-r-[a-z0-9]{12}$ ]]; then
            sudo userdel "$owned_account" >/dev/null 2>&1 || true
        fi
    done
    sudo systemctl disable --now mcp-gateway-reverse-sshd.service >/dev/null 2>&1 || true
    if sudo test -f /etc/mcp-gateway-reverse/manifest.json; then
        sudo rm -f /etc/systemd/system/mcp-gateway-reverse-sshd.service
        sudo rm -f /usr/local/libexec/mcp-gateway-reverse-key-reader
        sudo rm -rf /etc/mcp-gateway-reverse
        sudo userdel mcp-reverse >/dev/null 2>&1 || true
        sudo systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if [[ -n "$target_unit" ]]; then
        sudo rm -rf /var/lib/mcp-gateway-reverse
    fi
    sudo loginctl disable-linger deploy.prod >/dev/null 2>&1 || true
    sudo loginctl terminate-user deploy.prod >/dev/null 2>&1 || true
    sudo userdel -r deploy.prod >/dev/null 2>&1 || true
    sudo rm -rf -- "$tmp"
}
trap cleanup EXIT

touch "$DB_DATABASE"
sudo install -d -m 0755 /run/sshd
sudo useradd --badname --user-group --create-home --shell /bin/bash --password '*' deploy.prod
ssh-keygen -q -t ed25519 -N '' -C '' -f "$tmp/target-host"
cat > "$tmp/target-sshd.conf" <<EOF
Port $target_port
ListenAddress 127.0.0.1
PidFile $tmp/target.pid
HostKey $tmp/target-host
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowUsers deploy.prod
AllowTcpForwarding no
PermitRootLogin no
Subsystem sftp internal-sftp
EOF
sudo /usr/sbin/sshd -t -f "$tmp/target-sshd.conf"
sudo /usr/sbin/sshd -f "$tmp/target-sshd.conf" -E "$tmp/target.log"
[[ -f "$tmp/target.pid" ]] || die "Isolated Target SSHD did not start."

sudo bash bin/managed-reverse-gateway.sh --preflight --app "$PWD" \
    --php-user "$(id -un)" --port "$control_port"
sudo bash bin/managed-reverse-gateway.sh --apply --app "$PWD" \
    --php-user "$(id -un)" --port "$control_port"
sudo systemctl is-active --quiet mcp-gateway-reverse-sshd.service ||
    die "Managed control SSHD is not active."

php artisan migrate --force --no-interaction > "$tmp/migrate.log" 2>&1 ||
    { tail -45 "$tmp/migrate.log" >&2; die "Ephemeral SQLite migration failed."; }
php tests/Support/managed-reverse-e2e.php enroll ||
    die "Could not generate exact Target command from managed service."
[[ -s "$tmp/one-command.sh" && -s "$tmp/enrollment-id" ]] ||
    die "Enrollment command/identifier was not produced; stop before any Target effect."
enrollment="$(cat "$tmp/enrollment-id")"
[[ "$enrollment" =~ ^[0-9a-hjkmnp-tv-z]{26}$ ]] ||
    die "Generated enrollment ID is malformed."
target_unit="mcp-gateway-reverse-$enrollment.service"
control_user="mcp-r-$(printf '%s' "${enrollment:14:12}" | tr '[:upper:]' '[:lower:]')"

# Short-lived, private TLS bridge to an ordinary loopback Laravel HTTP
# process; no external endpoint or insecure curl -k.
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$tmp/tls.key" -out "$tmp/tls.crt" \
    -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
    >"$tmp/tls-keygen.log" 2>&1
cat "$tmp/tls.key" "$tmp/tls.crt" > "$tmp/tls.pem"
php artisan serve --host=127.0.0.1 --port="$app_port" \
    >"$tmp/laravel.log" 2>&1 &
php_pid="$!"
socat "OPENSSL-LISTEN:$tls_port,bind=127.0.0.1,reuseaddr,fork,cert=$tmp/tls.pem,verify=0" \
    "TCP:127.0.0.1:$app_port" >"$tmp/tls.log" 2>&1 &
tls_pid="$!"
ready=false
for i in {1..30}; do
    if CURL_CA_BUNDLE="$tmp/tls.crt" curl --proto '=https' \
        --fail --silent --max-time 2 "$APP_URL/reverse-ssh/installer/v1" \
        -o "$tmp/installer-check.sh"; then
        ready=true
        break
    fi
    sleep 0.3
done
[[ "$ready" == true ]] ||
    { tail -25 "$tmp/laravel.log" "$tmp/tls.log" >&2; die "Local HTTPS installer source unavailable."; }
sha256sum bin/managed-reverse-target.sh | awk '{print $1}' > "$tmp/expected-sha"
sha256sum "$tmp/installer-check.sh" | awk '{print $1}' > "$tmp/actual-sha"
cmp "$tmp/expected-sha" "$tmp/actual-sha" ||
    die "Live HTTPS installer source bytes differ from accepted release."

# Root-side managed-state preflight must reject pre-planted directories and
# unsafe lock files BEFORE opening any root-owned file or burning a claim.
target_pin="$(awk '{print $1" "$2}' "$tmp/target-host.pub" | base64 -w 0)"
state_dir="/var/lib/mcp-gateway-reverse/$enrollment"
sudo install -d -m 0755 /var/lib/mcp-gateway-reverse
sudo install -d -m 0711 "$state_dir"
sudo chown deploy.prod:deploy.prod "$state_dir"
if sudo env CURL_CA_BUNDLE="$tmp/tls.crt" bash bin/managed-reverse-target.sh \
    --gateway "$APP_URL" --enrollment "$enrollment" --token "$(printf '0%.0s' {1..64})" \
    --host-key-b64 "$target_pin" --target-port "$target_port" --target-user deploy.prod \
    > "$tmp/unsafe-owner.log" 2>&1; then
    die "Target installer adopted an attacker-owned managed state directory."
fi
grep -Fq 'Unsafe managed directory ownership' "$tmp/unsafe-owner.log" ||
    die "Unsafe state ownership was not specifically diagnosed."
sudo chown root:root "$state_dir"
sudo chmod 0733 "$state_dir"
if sudo env CURL_CA_BUNDLE="$tmp/tls.crt" bash bin/managed-reverse-target.sh \
    --gateway "$APP_URL" --enrollment "$enrollment" --token "$(printf '0%.0s' {1..64})" \
    --host-key-b64 "$target_pin" --target-port "$target_port" --target-user deploy.prod \
    > "$tmp/unsafe-mode.log" 2>&1; then
    die "Target installer adopted a group/world-writable managed state directory."
fi
sudo chmod 0711 "$state_dir"
protected_passwd="$(sudo sha256sum /etc/passwd | cut -d' ' -f1)"
sudo ln -s /etc/passwd "$state_dir/.install.lock"
if sudo env CURL_CA_BUNDLE="$tmp/tls.crt" bash bin/managed-reverse-target.sh \
    --gateway "$APP_URL" --enrollment "$enrollment" --token "$(printf '0%.0s' {1..64})" \
    --host-key-b64 "$target_pin" --target-port "$target_port" --target-user deploy.prod \
    > "$tmp/unsafe-lock.log" 2>&1; then
    die "Target installer followed a root-state lock symlink."
fi
grep -Fq 'Unsafe root-managed file' "$tmp/unsafe-lock.log" ||
    die "Unsafe lock file was not specifically diagnosed."
[[ "$(sudo sha256sum /etc/passwd | cut -d' ' -f1)" == "$protected_passwd" ]] ||
    die "Unsafe root lock redirection modified unrelated /etc/passwd."
sudo rm -- "$state_dir/.install.lock"
[[ ! -e "$state_dir/enrollment.json" ]] || die "Unsafe preflight consumed enrollment."
echo "PASS: untrusted root-state owner/mode and lock symlink rejected before claim and privileged writes."

# A user-writable symlink in Target's login home must be rejected BEFORE
# consuming even a valid-looking claim. Avoid any privileged writes through
# the Target user's home and leave the exact OS identity untouched.
sudo runuser -u deploy.prod -- ln -s /etc /home/deploy.prod/.ssh
if sudo env CURL_CA_BUNDLE="$tmp/tls.crt" bash bin/managed-reverse-target.sh \
    --gateway "$APP_URL" --enrollment "$enrollment" \
    --token "$(printf '0%.0s' {1..64})" \
    --host-key-b64 "$(awk '{print $1" "$2}' "$tmp/target-host.pub" | base64 -w 0)" \
    --target-port "$target_port" --target-user deploy.prod \
    > "$tmp/symlink-preflight.log" 2>&1; then
    die "Target installer adopted a user-controlled symlink."
fi
grep -Fq 'Symlinked Target login SSH key paths are unsafe.' "$tmp/symlink-preflight.log" ||
    die "Target installer did not specifically block the unsafe login path."
sudo runuser -u deploy.prod -- rm -f /home/deploy.prod/.ssh
[[ ! -e "/var/lib/mcp-gateway-reverse/$enrollment/enrollment.json" ]] ||
    die "Symlink preflight consumed an enrollment unexpectedly."
echo "PASS: unsafe Target SSH-home symlink is rejected before claim."

# A definitively rejected claim must not create an orphan OS identity. The
# next valid command may safely reuse the locally staged (unpublished) key.
bad_host_pin="$(awk '{print $1" "$2}' "$tmp/target-host.pub" | base64 -w 0)"
if sudo env CURL_CA_BUNDLE="$tmp/tls.crt" bash bin/managed-reverse-target.sh \
    --gateway "$APP_URL" --enrollment "$enrollment" \
    --token "$(printf '0%.0s' {1..64})" \
    --host-key-b64 "$bad_host_pin" --target-port "$target_port" \
    --target-user deploy.prod \
    > "$tmp/rejected.log" 2>&1; then
    die "Wrong one-use claim was accepted by Laravel."
fi
if getent passwd "$control_user" >/dev/null; then
    die "Rejected claim created an orphaned OS account."
fi
[[ ! -e "/var/lib/mcp-gateway-reverse/$enrollment/enrollment.json" ]] ||
    die "Rejected claim wrote a misleading successful enrollment record."
echo "PASS: rejected token fails before control-account provisioning."

# EXACT application-generated command executed as root; public test CA is
# explicitly trusted only by this disposable process. No shell secrets logged.
sudo env CURL_CA_BUNDLE="$tmp/tls.crt" sh "$tmp/one-command.sh" \
    > "$tmp/installer.log" 2>&1 || {
        sed -E 's/[a-f0-9]{64}/[REDACTED]/g' "$tmp/installer.log" >&2
        die "Single-command Target installer failed."
    }
sudo systemctl is-active --quiet "$target_unit" ||
    { sudo journalctl -u "$target_unit" -n 30 --no-pager >&2; die "Target systemd tunnel not running."; }
echo "PASS: exact generated command, HTTPS TLS + release digest, one-use claim and Target systemd activation."

# Exercise the recovery flow after an already successful but unverified
# one-use claim. The old complete root state and systemd unit still exist.
prior_unit="$target_unit"
prior_user="$control_user"
prior_id="$enrollment"
php tests/Support/managed-reverse-e2e.php reissue ||
    die "Owner could not reissue the claimed but unverified enrollment."
enrollment="$(cat "$tmp/enrollment-id")"
[[ "$enrollment" != "$prior_id" && "$enrollment" =~ ^[0-9a-hjkmnp-tv-z]{26}$ ]] ||
    die "Reissued Target installer identity was reused or invalid."
target_unit="mcp-gateway-reverse-$enrollment.service"
control_user="mcp-r-$(printf '%s' "$enrollment" | cut -c15-26)"
sudo systemctl is-active --quiet "$prior_unit" ||
    die "Previous Target unit was unexpectedly destroyed during Owner reissue."
sudo env CURL_CA_BUNDLE="$tmp/tls.crt" sh "$tmp/one-command.sh" \
    > "$tmp/reissued.log" 2>&1 || {
        sed -E 's/[a-f0-9]{64}/[REDACTED]/g' "$tmp/reissued.log" >&2
        die "New single command failed while old root-owned Target state still existed."
    }
sudo systemctl is-active --quiet "$target_unit" ||
    die "Reissued new Target unit did not start."
sudo systemctl disable --now "$prior_unit" >/dev/null ||
    die "Could not stop the exact superseded disposable Target service."
echo "PASS: reissued command used new root state/systemd/control account while retaining original Target identity."

listener="$(php -r '
require "vendor/autoload.php";
$app=require "bootstrap/app.php";
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
echo App\Infrastructure\Connectors\SshDirect\SshManagedReverseEnrollment::query()->sole()->listener_port;
')"
[[ "$listener" =~ ^[0-9]{4,5}$ ]] || die "Missing managed listener port."
ready=false
for i in {1..40}; do
    if ss -H -lnt | grep -Fq "127.0.0.1:$listener"; then
        ready=true
        break
    fi
    sleep 0.5
done
[[ "$ready" == true ]] || {
    sudo journalctl -u "$target_unit" -n 50 --no-pager >&2
    sudo journalctl -u mcp-gateway-reverse-sshd.service -n 35 --no-pager >&2
    die "Real systemd remote loopback listener did not become ready."
}

php tests/Support/managed-reverse-e2e.php verify
php tests/Support/managed-reverse-e2e.php readiness
sudo systemctl is-enabled --quiet "$target_unit" ||
    die "Target reverse service was not enabled for reboot persistence."
# The control SSHD is a different owned unit. Prove truthful unavailable
# diagnostics when that unit stops, then require a bounded reconnection.
sudo systemctl stop mcp-gateway-reverse-sshd.service
php tests/Support/managed-reverse-e2e.php readiness-stopped
sudo systemctl start mcp-gateway-reverse-sshd.service
for i in {1..45}; do
    if ss -H -lnt | grep -Fq "127.0.0.1:$listener"; then break; fi
    sleep 1
done
php tests/Support/managed-reverse-e2e.php readiness
sudo loginctl enable-linger deploy.prod
uid="$(id -u deploy.prod)"
job_runtime_ready=false
for i in {1..30}; do
    if sudo runuser -u deploy.prod -- env \
        XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        systemctl --user show-environment >/dev/null 2>&1; then
        job_runtime_ready=true
        break
    fi
    sleep 1
done
[[ "$job_runtime_ready" == true ]] || die "Dedicated Target login systemd --user manager did not start."
php tests/Support/managed-reverse-e2e.php job
echo "PASS: local pinned host readiness, degraded stopped SSHD state, reconnection and real managed retained Job."
# A second paste must not duplicate the Target OS user/service/key.
sudo env CURL_CA_BUNDLE="$tmp/tls.crt" sh "$tmp/one-command.sh" \
    > "$tmp/repeated.log" 2>&1 ||
    { sed -E 's/[a-f0-9]{64}/[REDACTED]/g' "$tmp/repeated.log" >&2; die "Safe local re-run failed."; }
[[ "$(getent passwd "$control_user" | wc -l)" -eq 1 ]] || die "Duplicated tunnel user."
[[ "$(sudo grep -c 'Managed by MCP Gateway Reverse SSH' "/etc/systemd/system/$target_unit")" -eq 1 ]] ||
    die "Duplicate or unowned service unit."

# Stop only the exact owned unit; no fallback to public direct 8.8.8.8.
sudo systemctl stop "$target_unit"
for i in {1..30}; do
    if ! ss -H -lnt | grep -Fq "127.0.0.1:$listener"; then break; fi
    sleep 0.3
done
php tests/Support/managed-reverse-e2e.php offline
sudo systemctl start "$target_unit"
for i in {1..40}; do
    if ss -H -lnt | grep -Fq "127.0.0.1:$listener"; then break; fi
    sleep 0.3
done
php tests/Support/managed-reverse-e2e.php verify
echo "PASS: exact Target re-run, bounded disconnect, reconnect and pinned Gateway Verify."

php tests/Support/managed-reverse-e2e.php revoke
# Route authorization is removed. Existing tunnel session is intentionally
# NOT assumed terminated just because the public key was removed.
[[ ! -s storage/app/private/ssh-reverse/authorized_keys ]] ||
    die "Control authorized-key reader still contains a revoked key."
echo "PASS: managed route revocation and local reader cleanup."
