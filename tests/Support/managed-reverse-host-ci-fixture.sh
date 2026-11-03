#!/usr/bin/env bash
# Disposable GitHub Actions runner only. Explicitly exercises the isolated
# root-owned host bootstrap and real restricted OpenSSH reverse forwarding.
set -Eeuo pipefail
umask 077
export LC_ALL=C

[[ "$EUID" -ne 0 ]] || { echo "Invoke as the normal CI runner, not root."; exit 1; }
[[ -n "${GITHUB_ACTIONS:-}" ]] || { echo "Refusing privileged host fixture outside disposable GitHub Actions."; exit 1; }
[[ -d /run/systemd/system ]] || { echo "systemd is not active."; exit 1; }
for command in sudo ssh sshd ssh-keygen ssh-keyscan curl python3 ss timeout; do
    command -v "$command" >/dev/null || { echo "Missing $command"; exit 1; }
done

port=45770 listener=46001 disallowed=46002 http_port=46003
tmp="$(mktemp -d /tmp/mcp-reverse-host-fixture.XXXXXXXX)"
php_user="$(id -un)"
app="$tmp/gateway"
unit="mcp-gateway-reverse-sshd.service"
tunnel_pid="" http_pid=""
cleanup() {
    [[ -z "$tunnel_pid" ]] || { kill "$tunnel_pid" 2>/dev/null || true; wait "$tunnel_pid" 2>/dev/null || true; }
    [[ -z "$http_pid" ]] || { kill "$http_pid" 2>/dev/null || true; wait "$http_pid" 2>/dev/null || true; }
    sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    if sudo test -f /etc/mcp-gateway-reverse/manifest.json; then
        sudo rm -f /etc/systemd/system/"$unit" /usr/local/libexec/mcp-gateway-reverse-key-reader
        sudo rm -rf /etc/mcp-gateway-reverse
        sudo userdel mcp-reverse >/dev/null 2>&1 || true
        sudo systemctl daemon-reload
    fi
    sudo rm -rf -- "$tmp"
}
trap cleanup EXIT

[[ ! -e /etc/mcp-gateway-reverse && ! -e /etc/systemd/system/"$unit" ]] ||
    { echo "The disposable runner already contains a control SSHD. Refusing takeover."; exit 1; }
mkdir -p "$app/storage/app"
bootstrap="$PWD/bin/managed-reverse-gateway.sh"
# Negative root-safety proof: PHP-owned symlinks cannot turn a bootstrap
# preflight into root chmod/chown of /etc or any other unrelated path.
protected_state="$(sudo stat -c '%u:%g:%a' /etc)"
ln -s /etc "$app/storage/app/private"
if sudo bash "$bootstrap" --preflight --app "$app" --php-user "$php_user" --port "$port" \
    > "$tmp/symlink-rejected.log" 2>&1; then
    echo "ERROR: Root bootstrap followed a writable PHP storage symlink."
    exit 1
fi
[[ "$(sudo stat -c '%u:%g:%a' /etc)" == "$protected_state" ]] ||
    { echo "Root bootstrap changed unrelated /etc metadata."; exit 1; }
rm -f -- "$app/storage/app/private"
echo "PASS: privileged bootstrap rejects PHP-owned storage symlink before side effects."
sudo bash "$bootstrap" --preflight --app "$app" --php-user "$php_user" --port "$port"
sudo bash "$bootstrap" --apply --app "$app" --php-user "$php_user" --port "$port"
sudo systemctl is-active --quiet "$unit"
# Capture the full output before asserting. A grep -q pipeline under
# pipefail can SIGPIPE sshd -T and falsely fail an otherwise correct host.
effective="$(sudo /usr/sbin/sshd -T -f /etc/mcp-gateway-reverse/sshd_config \
    -C user=mcp-reverse,host=localhost,addr=127.0.0.1)"
printf '%s\n' "$effective" | grep -E '^(allowtcpforwarding|permitlisten|gatewayports|passwordauthentication|permitopen|kbdinteractiveauthentication|usepam) ' >&2
grep -Fxq 'passwordauthentication no' <<< "$effective" ||
    { echo "Password login was enabled on restricted SSHD." >&2; exit 1; }
grep -Fxq 'kbdinteractiveauthentication no' <<< "$effective" ||
    { echo "Interactive PAM password login was enabled." >&2; exit 1; }
grep -Fxq 'allowtcpforwarding remote' <<< "$effective" ||
    { echo "Incorrect effective remote-only forwarding policy." >&2; exit 1; }
grep -Fxq 'permitlisten 127.0.0.1:*' <<< "$effective" ||
    { echo "Incorrect effective per-host loopback listener policy." >&2; exit 1; }

# Host-control secret created only on disposable Test Target side.
ssh-keygen -q -t ed25519 -N '' -f "$tmp/control.key" -C ''
public="$(awk '{print $1" "$2}' "$tmp/control.key.pub")"
key_file="$app/storage/app/private/ssh-reverse/authorized_keys"
printf 'restrict,port-forwarding,permitlisten="127.0.0.1:%d" %s\n' "$listener" "$public" > "$key_file"
chmod 0600 "$key_file"
scan="$(ssh-keyscan -T 5 -p "$port" 127.0.0.1 2>/dev/null || true)"
[[ -n "$scan" ]] || { echo "Control host key did not respond."; exit 1; }
printf '%s\n' "$scan" > "$tmp/known_hosts"

mkdir "$tmp/web"
printf 'managed-reverse-fixture-ok\n' > "$tmp/web/index.html"
(
    cd "$tmp/web"
    exec python3 -m http.server "$http_port" --bind 127.0.0.1 >"$tmp/http.log" 2>&1
) &
http_pid="$!"
sleep 1

common=(-p "$port" -i "$tmp/control.key" -o BatchMode=yes -o IdentitiesOnly=yes
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$tmp/known_hosts"
        -o ExitOnForwardFailure=yes -o ConnectTimeout=5)
ssh -N -T "${common[@]}" -R "127.0.0.1:$listener:127.0.0.1:$http_port" \
    mcp-reverse@127.0.0.1 >"$tmp/ssh.log" 2>&1 &
tunnel_pid="$!"
ready=false
for attempt in {1..20}; do
    if curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:$listener/" \
        2>/dev/null | grep -Fq managed-reverse-fixture-ok; then
        ready=true
        break
    fi
    sleep 0.5
done
[[ "$ready" == true ]] || {
    cat "$tmp/ssh.log"
    sudo journalctl -u "$unit" -n 40 --no-pager || true
    echo "Loopback reverse forward never succeeded."
    exit 1
}
ss -H -lnt | awk '{print $4}' | grep -Eq "127\\.0\\.0\\.1:$listener$"

# A different remote listener must be rejected by the exact authorized_keys
# permitlisten policy, even with the same authenticated private key.
if timeout 8 ssh -N -T "${common[@]}" -R "127.0.0.1:$disallowed:127.0.0.1:$http_port" \
  mcp-reverse@127.0.0.1 >"$tmp/wrong-port.log" 2>&1; then
    echo "ERROR: Unapproved reverse listener accepted."; exit 1
fi
# SSH command execution is never allowed on the restricted control identity.
if timeout 8 ssh -T "${common[@]}" mcp-reverse@127.0.0.1 \
    /usr/bin/id >"$tmp/shell.log" 2>&1; then
    echo "ERROR: Restricted control identity executed a command."; exit 1
fi

# Host-key mismatch must reject auth before any SSH control key is used.
ssh-keygen -q -t ed25519 -N '' -f "$tmp/wrong-host.key" -C ''
printf '[127.0.0.1]:%s %s\n' "$port" "$(awk '{print $1" "$2}' "$tmp/wrong-host.key.pub")" > "$tmp/wrong-known_hosts"
if timeout 8 ssh -N -T -p "$port" -i "$tmp/control.key" \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$tmp/wrong-known_hosts" -o ExitOnForwardFailure=yes \
    -R "127.0.0.1:$disallowed:127.0.0.1:$http_port" \
    mcp-reverse@127.0.0.1 > "$tmp/mitm.log" 2>&1; then
    echo "ERROR: Wrong SSHD host key was accepted."; exit 1
fi

# Revocation prevents NEW control logins; existing sessions can stay up.
: > "$key_file"
curl --fail --silent --max-time 2 "http://127.0.0.1:$listener/" | grep -Fq managed-reverse-fixture-ok
kill "$tunnel_pid" 2>/dev/null || true
wait "$tunnel_pid" 2>/dev/null || true
tunnel_pid=""
if timeout 8 ssh -N -T "${common[@]}" -R "127.0.0.1:$listener:127.0.0.1:$http_port" \
    mcp-reverse@127.0.0.1 >"$tmp/revoked.log" 2>&1; then
    echo "ERROR: Revoked key still authenticated."; exit 1
fi
# A disable request with the wrong port must never stop an unrelated
# listener; exact root-owned manifest identity is required for shutdown.
if sudo bash "$bootstrap" --disable --app "$app" --php-user "$php_user" \
    --port "$((port + 1))" > "$tmp/wrong-disable.log" 2>&1; then
    echo "ERROR: Incorrect Gateway bootstrap identity stopped SSHD."; exit 1
fi
sudo systemctl is-active --quiet "$unit" ||
    { echo "ERROR: Incorrect disable changed control SSHD state."; exit 1; }
sudo bash "$bootstrap" --disable --app "$app" --php-user "$php_user" \
    --port "$port" > "$tmp/right-disable.log" 2>&1
if sudo systemctl is-active --quiet "$unit"; then
    echo "ERROR: Approved disable left the restricted SSHD running."; exit 1
fi
echo "PASS: exact-identity disable stops only the owned control SSHD."

echo "PASS: actual isolated SSHD bootstrap, loopback forwarding, exact port, no shell and new-login revocation."
