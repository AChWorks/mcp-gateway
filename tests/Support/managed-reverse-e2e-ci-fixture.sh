#!/usr/bin/env bash
# Exact generated one-command onboarding on a disposable GitHub-hosted
# systemd runner. Not suitable for a live Gateway or an operator server.
set -Eeuo pipefail
umask 077
export LC_ALL=C

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ "\${GITHUB_ACTIONS:-}" == true && "$EUID" -ne 0 ]] ||
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
getent passwd mcptargetci >/dev/null && die "Fixture test account already exists."
getent passwd mcp-reverse >/dev/null && die "Gateway control account already exists."

tmp="$(mktemp -d /tmp/mcp-managed-e2e.XXXXXXXX)"
control_port=45770
target_port=45691
app_port=44801
tls_port=44999
target_id="ci-managed-reverse"
target_unit=""
control_user=""
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
    if [[ -n "$target_unit" && "$target_unit" =~ ^mcp-gateway-reverse-[0-9A-HJKMNP-TV-Z]{26}\.service$ ]]; then
        sudo systemctl disable --now "$target_unit" >/dev/null 2>&1 || true
        sudo rm -f -- "/etc/systemd/system/$target_unit"
        sudo systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if [[ -f "$tmp/target.pid" ]]; then
        local pid
        pid="$(cat "$tmp/target.pid")"
        [[ "$pid" =~ ^[0-9]+$ ]] && sudo kill "$pid" 2>/dev/null || true
    fi
    if [[ -n "$control_user" && "$control_user" =~ ^mcp-r-[a-z0-9]{12}$ ]]; then
        sudo userdel "$control_user" >/dev/null 2>&1 || true
    fi
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
    sudo userdel -r mcptargetci >/dev/null 2>&1 || true
    sudo rm -rf -- "$tmp"
}
trap cleanup EXIT

touch "$DB_DATABASE"
sudo install -d -m 0755 /run/sshd
sudo useradd --user-group --create-home --shell /bin/bash --password '*' mcptargetci
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
AllowUsers mcptargetci
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
enrollment="$(cat "$tmp/enrollment-id")"
[[ "$enrollment" =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] ||
    die "Generated enrollment ID is malformed."
target_unit="mcp-gateway-reverse-$enrollment.service"
control_user="mcp-r-$(printf '%s' "\${enrollment:0:12}" | tr '[:upper:]' '[:lower:]')"

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
