#!/usr/bin/env bash
# Target-side installer for one Owner-enrolled MCP Gateway Reverse SSH route.
# Run only after verifying the immutable installer digest shown in Admin.
set -Eeuo pipefail
umask 077
export LC_ALL=C

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
notice() { printf '%s\n' "$*" >&2; }
usage() {
    cat >&2 <<'HELP'
Usage: bash managed-reverse-target.sh --gateway https://gateway.example --enrollment ULID --token HEX64 --host-key-b64 BASE64 [--target-port N]
Requires explicit root privileges; supports Debian/Ubuntu and RHEL-family with systemd.
HELP
    exit 2
}
gateway="" enrollment="" token="" host_key_b64="" port_override=""
while (($#)); do
    case "$1" in
        --gateway) (($# >= 2)) || usage; gateway="$2"; shift 2 ;;
        --enrollment) (($# >= 2)) || usage; enrollment="$2"; shift 2 ;;
        --token) (($# >= 2)) || usage; token="$2"; shift 2 ;;
        --host-key-b64) (($# >= 2)) || usage; host_key_b64="$2"; shift 2 ;;
        --target-port) (($# >= 2)) || usage; port_override="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$EUID" -eq 0 ]] || die "Run with sudo/root; no privilege escalation is attempted."
[[ "$gateway" =~ ^https://[A-Za-z0-9.:-]+(:[0-9]+)?(/[^\ \?\#]*)?$ ]] || die "Gateway must be an explicit HTTPS endpoint."
[[ "$enrollment" =~ ^[0-9a-hjkmnp-tv-z]{26}$ ]] || die "Invalid enrollment identity."
[[ "$token" =~ ^[a-f0-9]{64}$ ]] || die "Invalid one-use enrollment authorization."
[[ "$host_key_b64" =~ ^[A-Za-z0-9+/=]+$ ]] || die "Invalid verified Target host key encoding."
[[ -z "$port_override" || "$port_override" =~ ^[1-9][0-9]{0,4}$ ]] || die "Invalid SSH port override."
[[ -r /etc/os-release ]] || die "Unsupported host: /etc/os-release missing."
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu|rhel|rocky|almalinux|centos|fedora) ;;
    *) die "Unsupported distribution ${ID:-unknown}; no changes made." ;;
esac
[[ -d /run/systemd/system ]] || die "systemd must be the active init manager; no changes made."
for program in curl ssh ssh-keygen ssh-keyscan systemctl python3 getent id useradd install chown chmod flock; do
    command -v "$program" >/dev/null 2>&1 || die "Required tool missing: $program (install it before retrying)."
done
[[ -x /usr/bin/ssh ]] || die "Supported OpenSSH client must be installed at /usr/bin/ssh."
declare -r base_dir="/var/lib/mcp-gateway-reverse"
declare -r state_dir="$base_dir/$enrollment"
declare -r state_file="$state_dir/enrollment.json"
declare -r keys_dir="$state_dir/ssh"
declare -r control_key="$keys_dir/control"
declare -r unit="/etc/systemd/system/mcp-gateway-reverse-$enrollment.service"
declare -r client_user="mcp-r-$(printf '%s' "${enrollment:0:12}" | tr '[:upper:]' '[:lower:]')"
declare -r api="${gateway%/}/reverse-ssh/enroll/$enrollment/claim"
[[ ! -L "$base_dir" && ! -L "$state_dir" && ! -L "$keys_dir" ]] || die "Symlinked managed state path refused."
[[ ! -e "$unit" || -f "$unit" && ! -L "$unit" ]] || die "Unexpected service unit type."
# In a fresh run no Target system files are touched until local SSH identity is
# observed and compared against the independently Owner-confirmed pin.
owner_pin="$(printf '%s' "$host_key_b64" | base64 --decode)" || die "Cannot decode verified Target host key."
[[ "$owner_pin" =~ ^ssh-(ed25519|rsa)[[:space:]][A-Za-z0-9+/=]+$ || "$owner_pin" =~ ^ecdsa-sha2-nistp[0-9]+[[:space:]][A-Za-z0-9+/=]+$ ]] || die "Invalid host pin."
# The Owner separately entered the expected Target endpoint port. A local
# override is only needed if that port is not the sshd listening interface.
local_port="${port_override:-22}"
[[ "$local_port" -ge 1 && "$local_port" -le 65535 ]] || die "SSH port outside 1..65535."
scan="$(ssh-keyscan -T 5 -p "$local_port" 127.0.0.1 2>/dev/null || true)"
[[ -n "$scan" ]] || die "Local SSHD not reachable; specify --target-port if nonstandard."
if ! printf '%s\n' "$scan" | awk '{print $2" "$3}' | grep -Fxq "$owner_pin"; then
    die "Local SSHD host key does not match the Owner-verified Target pin. No changes made."
fi
# Local data written after preflight; all managed paths are ownable and
# reconciled on repeat execution, never adopt an unrelated service/unit.
if [[ -e "$state_file" ]]; then
    [[ -f "$state_file" && ! -L "$state_file" ]] || die "Unexpected existing enrollment state."
fi
# Before consuming the one-use claim, refuse an unrelated OS account or
# pre-existing systemd unit. A first installation creates the dedicated OS
# user ONLY after the claim response is stored, so a lost response does not
# leave an orphaned account that prevents safe Owner reconciliation.
if getent passwd "$client_user" >/dev/null; then
    [[ -f "$state_file" ]] || die "Existing service user has no completed enrollment state; request Owner reconciliation."
    [[ "$(id -gn "$client_user")" == "$client_user" ]] ||
        die "Existing control account lacks its dedicated service group."
fi
if [[ -e "$unit" && $(grep -cx '# Managed by MCP Gateway Reverse SSH' "$unit" || true) != 1 ]]; then
    die "Existing systemd unit is not owned by this enrollment; no overwrite."
fi
install -d -m 0755 "$base_dir"
install -d -m 0711 "$state_dir"
exec 9> "$state_dir/.install.lock"
flock -n 9 || die "Another installer is already running for this enrollment."
install -d -m 0700 "$keys_dir"
if [[ ! -f "$control_key" ]]; then
    ssh-keygen -q -t ed25519 -N '' -f "$control_key" -C "" || die "SSH key creation failed."
fi
[[ -f "$control_key" && ! -L "$control_key" && -f "$control_key.pub" && ! -L "$control_key.pub" ]] || die "Unexpected tunnel key layout."
chmod 0600 "$control_key"
chmod 0644 "$control_key.pub"
# The token never appears in the HTTP URL, access log route, or public artifact.
# The request file is private and deleted immediately after use.
tmp_request="$state_dir/.request.$$"
cleanup() { rm -f "$tmp_request"; }
trap cleanup EXIT
if [[ ! -f "$state_file" ]]; then
    python3 - "$token" "$control_key.pub" "$tmp_request" <<'PYTHON'
import json, pathlib, sys
token, pub, outfile = sys.argv[1:]
key = " ".join(pathlib.Path(pub).read_text().split()[:2])
with open(outfile, "x", encoding="utf-8") as handle:
    json.dump({"token": token, "public_key": key}, handle)
PYTHON
    # Never automatically retry: an ambiguous network result may have
    # consumed the token. Owner reconciliation is required if no response.
    tmp_response="$state_dir/.response.$$"
    if ! curl --proto '=https' --tlsv1.2 -fsS --connect-timeout 8 --max-time 25 \
        -H 'Content-Type: application/json' -H 'Accept: application/json' \
        --request POST --data-binary "@$tmp_request" --output "$tmp_response" "$api"; then
        rm -f "$tmp_response"
        die "Gateway claim failed or is uncertain. Do not retry with a new key/token; ask Owner to reconcile."
    fi
    mv -n -- "$tmp_response" "$state_file" || die "Failed to persist claimed enrollment response."
    chmod 0600 "$state_file"
fi
# The response is durable BEFORE creating an OS account. Explicit
# --user-group avoids relying on distro-specific USERGROUPS_ENAB defaults.
# Do not silently adopt an existing account without proven owned state.
if ! getent passwd "$client_user" >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir "$state_dir" \
        --shell /usr/sbin/nologin "$client_user" ||
        die "Could not create the dedicated non-root tunnel account."
fi
[[ "$(id -gn "$client_user")" == "$client_user" ]] ||
    die "Dedicated tunnel service group does not match its account."
chown -R "$client_user:$client_user" "$keys_dir"
chmod 0700 "$keys_dir"

# Parse untrusted JSON as data, NEVER evaluate as shell. Strict fields only.
params="$state_dir/.parameters.$$"
python3 - "$state_file" "$params" <<'PYTHON' || die "Invalid Gateway claim response; reconcile with Owner."
import base64, json, pathlib, re, sys
response, output = sys.argv[1:]
data = json.loads(pathlib.Path(response).read_text())
assert data.get("state") == "control_key_activated" and data.get("verified") is False
names = ("control_host", "control_port", "control_user", "control_host_key",
         "listener_port", "target_port", "target_username", "login_public_key")
for key in names:
    assert key in data, key
assert re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", data["control_host"])
assert re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", data["control_user"])
assert re.fullmatch(r"[a-z_][a-z0-9_-]{0,127}", data["target_username"])
for key in ("control_port", "listener_port", "target_port"):
    assert type(data[key]) is int and 1 <= data[key] <= 65535
for key in ("control_host_key", "login_public_key"):
    assert re.fullmatch(r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+", data[key])
with open(output, "x", encoding="utf-8") as dest:
    for key in names:
        dest.write(str(data[key]) + "\n")
PYTHON
mapfile -t params_data < "$params"
rm -f "$params"
control_host="${params_data[0]}" control_port="${params_data[1]}"
control_user="${params_data[2]}" control_host_key="${params_data[3]}"
listener_port="${params_data[4]}" registered_port="${params_data[5]}"
target_user="${params_data[6]}" login_public_key="${params_data[7]}"
[[ "$registered_port" -eq "$local_port" ]] || die "Selected Target SSH port mismatches registered enrollment; use --target-port $registered_port."
getent passwd "$target_user" >/dev/null || die "The explicitly selected Target login account does not exist: $target_user."
target_home="$(getent passwd "$target_user" | awk -F: '{print $6}')"
[[ "$target_home" = /* && -d "$target_home" && ! -L "$target_home" ]] || die "Target login home is missing/unsafe."
login_ssh="$target_home/.ssh"
login_keys="$login_ssh/authorized_keys"
[[ ! -L "$login_ssh" && ! -L "$login_keys" ]] || die "Refusing symlinked Target authorized_keys path."
[[ ! -e "$login_keys" || -f "$login_keys" ]] || die "Unexpected authorized_keys type."
install -d -m 0700 -o "$target_user" "$login_ssh"
touch "$login_keys"
chown "$target_user" "$login_keys"
chmod 0600 "$login_keys"
if ! grep -Fxq -- "$login_public_key" "$login_keys"; then
    printf '%s\n' "$login_public_key" >> "$login_keys"
fi
# OpenSSH checks this independent pinned Gateway *control* server key.
known="$keys_dir/known_hosts"
[[ ! -L "$known" ]] || die "Symlinked known_hosts path refused."
printf '[%s]:%s %s\n' "$control_host" "$control_port" "$control_host_key" > "$known"
chmod 0600 "$known"
chown -R "$client_user" "$keys_dir"
tmp_unit="$state_dir/.service.$$"
cat > "$tmp_unit" <<EOF
# Managed by MCP Gateway Reverse SSH
[Unit]
Description=MCP Gateway Reverse SSH (Target enrollment $enrollment)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$client_user
Group=$client_user
ExecStart=/usr/bin/ssh -N -T -i $control_key -p $control_port -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known -o ExitOnForwardFailure=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -o ConnectTimeout=12 -R 127.0.0.1:$listener_port:127.0.0.1:$registered_port $control_user@$control_host
Restart=always
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$keys_dir

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$tmp_unit" "$unit"
rm -f "$tmp_unit"
systemctl daemon-reload
systemctl enable --now "mcp-gateway-reverse-$enrollment.service" >/dev/null
systemctl is-active --quiet "mcp-gateway-reverse-$enrollment.service" ||
    die "Service did not start; inspect journalctl -u mcp-gateway-reverse-$enrollment. Gateway Verify still required."
notice "Reverse SSH service started locally. Open Gateway Target Details and Verify the real SSH host key/login."
notice "A running service is NOT proof that Gateway is connected; recheck after reboot/network loss."
