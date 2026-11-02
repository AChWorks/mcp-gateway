#!/usr/bin/env bash
# One-time, Owner-authorized Gateway HOST bootstrap. Never invoked by PHP.
# Installs an isolated OpenSSH listener, not edits to the existing sshd.
set -Eeuo pipefail
umask 077
export LC_ALL=C

die() { echo "ERROR: $*" >&2; exit 1; }
action="" app="" php_user="" port="" control_user="mcp-reverse"
while (($#)); do
    case "$1" in
        --preflight|--apply|--disable) [[ -z "$action" ]] || die "One action only."; action="$1"; shift ;;
        --app) (($# > 1)) || die "Missing --app value."; app="$2"; shift 2 ;;
        --php-user) (($# > 1)) || die "Missing --php-user value."; php_user="$2"; shift 2 ;;
        --port) (($# > 1)) || die "Missing --port value."; port="$2"; shift 2 ;;
        --control-user) (($# > 1)) || die "Missing --control-user value."; control_user="$2"; shift 2 ;;
        *) die "Unknown option $1" ;;
    esac
done
[[ "$EUID" -eq 0 ]] || die "Explicit sudo/root approval required."
[[ "$action" == --preflight || "$action" == --apply || "$action" == --disable ]] || die "Select --preflight, --apply or --disable."
[[ "$control_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Invalid control user."
[[ "$port" =~ ^[0-9]{4,5}$ && "$port" -ge 1024 && "$port" -le 65535 ]] || die "Control port must be 1024..65535."
[[ "$php_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Invalid PHP worker identity."
[[ "$app" =~ ^/[a-zA-Z0-9/_.-]+$ && "$app" != *'..'* ]] || die "Provide the real absolute application path with --app."
[[ -r /etc/os-release ]] || die "Unsupported Linux host."
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in debian|ubuntu|rhel|rocky|almalinux|centos|fedora) ;; *) die "Unsupported Linux distribution." ;; esac
[[ -d /run/systemd/system ]] || die "systemd must be PID 1."
for tool in sshd ssh-keygen systemctl getent install useradd python3 stat; do
    command -v "$tool" >/dev/null || die "Missing required tool: $tool."
done
getent passwd "$php_user" >/dev/null || die "PHP worker account does not exist."
[[ "$php_user" != root && "$control_user" != root && "$php_user" != "$control_user" ]] ||
    die "Use separate non-root PHP and control identities."
[[ -d "$app/storage" && ! -L "$app/storage" ]] || die "Application storage path is absent/unsafe."
ssh_bin="$(command -v sshd)"
[[ -x "$ssh_bin" ]] || die "OpenSSH server unavailable."
root_dir="/etc/mcp-gateway-reverse"
reader="/usr/local/libexec/mcp-gateway-reverse-key-reader"
unit="/etc/systemd/system/mcp-gateway-reverse-sshd.service"
config="$root_dir/sshd_config"
host_key="$root_dir/ssh_host_ed25519_key"
manifest="$root_dir/manifest.json"
keyfile="$app/storage/app/private/ssh-reverse/authorized_keys"
# Neither existing global sshd configuration nor firewall are modified.
if [[ ! -f "$manifest" ]] && getent passwd "$control_user" >/dev/null 2>&1; then
    die "Pre-existing control account is not owned by a managed Gateway installation."
fi
if [[ ! -f "$manifest" && -s "$keyfile" ]]; then
    die "Pre-existing nonempty key file cannot be adopted without Gateway ownership evidence."
fi
if [[ "$action" == --disable ]]; then
    [[ -f "$manifest" && ! -L "$manifest" ]] || die "No owned Gateway bootstrap found; refusing unrelated service changes."
    systemctl disable --now mcp-gateway-reverse-sshd.service
    echo "Restricted control sshd disabled. Existing SSH service unchanged."
    exit 0
fi
if [[ -e "$manifest" ]]; then
    [[ -f "$manifest" && ! -L "$manifest" ]] || die "Unknown existing bootstrap manifest."
    python3 - "$manifest" "$port" "$control_user" "$keyfile" <<'PYTHON'
import json, pathlib, sys
manifest, port, user, keyfile = sys.argv[1:]
current = json.loads(pathlib.Path(manifest).read_text())
assert current.get("version") == 1
assert current["control_port"] == int(port) and current["control_user"] == user
assert current["authorized_keys_file"] == keyfile
PYTHON
elif [[ -e "$root_dir" || -e "$unit" || -e "$reader" || -e "$host_key" ]]; then
    die "Partial or unrelated prior installation found. Inspect and repair manually before mutation."
fi
# Explicit preflight: does not create any account, sshd config, key or service.
if [[ "$action" == --preflight ]]; then
    echo "PRECHECK: distro=${ID}; systemd=present; OpenSSH=$(ssh -V 2>&1 || true)"
    echo "PRECHECK: app=$app, PHP=$php_user, control=$control_user, port=$port"
    [[ ! -e "$unit" || -f "$manifest" ]] || die "Existing unmanaged unit."
    if [[ ! -f "$manifest" ]] && command -v ss >/dev/null && ss -H -lnt | awk '{print $4}' | grep -Eq "[:.]$port$"; then
        die "Requested control port is already listening; select another port."
    fi
    echo "PRECHECK OK: host setup is optional; --apply makes explicit system changes."
    exit 0
fi
[[ ! -e "$unit" || -f "$manifest" ]] || die "Unmanaged systemd unit present."
if [[ ! -f "$manifest" ]] && command -v ss >/dev/null &&
    ss -H -lnt | awk '{print $4}' | grep -Eq "[:.]$port$"; then
    die "Port is already in use; will not displace another service."
fi
if ! getent passwd "$control_user" >/dev/null; then
    # OpenSSH with UsePAM=no refuses a shadow entry beginning with "!" even
    # for key-only login. "*" is an impossible password hash (no password
    # login), while allowing strictly scoped SSH public-key authentication.
    useradd --system --no-create-home --shell /usr/sbin/nologin --password '*' "$control_user"
fi
install -d -m 0755 "$root_dir" "$(dirname "$reader")"
if [[ ! -f "$host_key" ]]; then
    ssh-keygen -q -t ed25519 -N '' -f "$host_key" -C "" || die "Cannot generate isolated SSHD host key."
fi
[[ ! -L "$host_key" && ! -L "$host_key.pub" ]] || die "Symlinked control SSHD key refused."
chmod 0600 "$host_key"
install -d -m 0700 -o "$php_user" "$app/storage/app/private/ssh-reverse"
if [[ ! -e "$keyfile" ]]; then
    install -m 0600 -o "$php_user" /dev/null "$keyfile"
fi
[[ -f "$keyfile" && ! -L "$keyfile" ]] || die "Managed authorized_keys path is not a regular file."
[[ "$(stat -c '%U' "$keyfile")" = "$php_user" ]] || die "Managed key file belongs to a different owner."
chmod 0600 "$keyfile"
# A root-owned fixed reader runs as the unprivileged PHP identity. It can
# print only the exact Gateway-owned public-key policy file; no arbitrary args.
cat > "$reader" <<EOF
#!/bin/sh
[ "\$1" = "$control_user" ] || exit 0
exec /bin/cat "$keyfile"
EOF
chown root:root "$reader"
chmod 0755 "$reader"
cat > "$config" <<EOF
Port $port
ListenAddress 0.0.0.0
Protocol 2
HostKey $host_key
PidFile /run/mcp-gateway-reverse-sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
AllowUsers $control_user
AuthorizedKeysFile none
AuthorizedKeysCommand $reader %u
AuthorizedKeysCommandUser $php_user
PermitTTY no
MaxSessions 0
ForceCommand /bin/false
AllowTcpForwarding remote
PermitListen 127.0.0.1:*
GatewayPorts no
PermitOpen none
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
AllowStreamLocalForwarding no
PermitUserEnvironment no
UsePAM yes
LogLevel VERBOSE
EOF
chown root:root "$config"
chmod 0600 "$config"
# Some clean systemd hosts have OpenSSH installed without ever starting the
# default ssh.service; OpenSSH still needs its standard privilege separation
# runtime directory even for a dedicated -f configuration.
if [[ -L /run/sshd || ( -e /run/sshd && ! -d /run/sshd ) ]]; then
    die "Unsafe OpenSSH privilege separation runtime directory /run/sshd."
fi
install -d -m 0755 -o root -g root /run/sshd
[[ "$(stat -c '%u:%g:%a' /run/sshd)" = '0:0:755' ]] ||
    die "Unexpected /run/sshd owner/mode; SSHD was not started."
"$ssh_bin" -t -f "$config" || die "Isolated sshd syntax invalid; existing host sshd is untouched."
"$ssh_bin" -T -f "$config" -C "user=$control_user,host=localhost,addr=127.0.0.1" |
    grep -Eq '^allowtcpforwarding remote$' || die "Effective SSHD remote-only forwarding check failed."
cat > "$unit" <<EOF
# Managed by MCP Gateway Reverse SSH (isolated control sshd)
[Unit]
Description=MCP Gateway restricted Reverse SSH control
After=network.target

[Service]
Type=simple
ExecStart=$ssh_bin -D -e -f $config
Restart=on-failure
RestartSec=5
RuntimeDirectory=mcp-gateway-reverse-sshd
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$unit"
systemctl daemon-reload
systemctl enable mcp-gateway-reverse-sshd.service >/dev/null
# A repair reuses only our owned unit, but must actually apply the verified
# config. This restarts ONLY the dedicated Gateway control SSHD.
systemctl restart mcp-gateway-reverse-sshd.service
systemctl is-active --quiet mcp-gateway-reverse-sshd.service ||
    die "Isolated sshd did not start; run systemctl status mcp-gateway-reverse-sshd."
# This root-owned identity record cannot be forged by an unprivileged PHP-FPM
# instance. Admin must match its host key and control port/user before enabling.
python3 - "$manifest" "$port" "$control_user" "$keyfile" "$host_key.pub" <<'PYTHON'
import json, os, pathlib, sys
dest, port, user, keyfile, keypath = sys.argv[1:]
hostkey = " ".join(pathlib.Path(keypath).read_text().split()[:2])
data = {"version": 1, "control_port": int(port), "control_user": user,
        "control_host_key": hostkey, "authorized_keys_file": keyfile}
tmp = dest + ".new"
with open(tmp, "x", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, dest)
PYTHON
echo "SETUP COMPLETE: restricted control sshd active on TCP $port."
echo "Control SSHD public key (verify by a trusted channel and enter in Owner Admin settings):"
awk '{print $1" "$2}' "$host_key.pub"
echo "Firewall/network reachability and the real SSHD restrictions must be verified separately."
