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
Usage: bash managed-reverse-target.sh --gateway https://gateway.example --enrollment ULID --token HEX64 --host-key-b64 BASE64 [--target-user USER] [--target-port N]
Requires explicit root privileges; supports Debian/Ubuntu and RHEL-family with systemd.
HELP
    exit 2
}
gateway="" enrollment="" token="" host_key_b64="" port_override="" expected_user=""
while (($#)); do
    case "$1" in
        --gateway) (($# >= 2)) || usage; gateway="$2"; shift 2 ;;
        --enrollment) (($# >= 2)) || usage; enrollment="$2"; shift 2 ;;
        --token) (($# >= 2)) || usage; token="$2"; shift 2 ;;
        --host-key-b64) (($# >= 2)) || usage; host_key_b64="$2"; shift 2 ;;
        --target-port) (($# >= 2)) || usage; port_override="$2"; shift 2 ;;
        --target-user) (($# >= 2)) || usage; expected_user="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$EUID" -eq 0 ]] || die "Run with sudo/root; no privilege escalation is attempted."
[[ "$gateway" =~ ^https://[A-Za-z0-9.:-]+(:[0-9]+)?(/[^\ \?\#]*)?$ ]] || die "Gateway must be an explicit HTTPS endpoint."
[[ "$enrollment" =~ ^[0-9a-hjkmnp-tv-z]{26}$ ]] || die "Invalid enrollment identity."
[[ "$token" =~ ^[a-f0-9]{64}$ ]] || die "Invalid one-use enrollment authorization."
[[ "$host_key_b64" =~ ^[A-Za-z0-9+/=]+$ ]] || die "Invalid verified Target host key encoding."
[[ -z "$port_override" || "$port_override" =~ ^[1-9][0-9]{0,4}$ ]] || die "Invalid SSH port override."
[[ -z "$expected_user" || "$expected_user" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.+-]{0,127}$ ]] ||
    die "Invalid enrolled SSH login username."
[[ -r /etc/os-release ]] || die "Unsupported host: /etc/os-release missing."
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu|rhel|rocky|almalinux|centos|fedora) ;;
    *) die "Unsupported distribution ${ID:-unknown}; no changes made." ;;
esac
[[ -d /run/systemd/system ]] || die "systemd must be the active init manager; no changes made."
for program in curl ssh ssh-keygen ssh-keyscan systemctl python3 getent id useradd runuser install chown chmod flock; do
    command -v "$program" >/dev/null 2>&1 || die "Required tool missing: $program (install it before retrying)."
done
[[ -x /usr/bin/ssh ]] || die "Supported OpenSSH client must be installed at /usr/bin/ssh."
declare -r base_dir="/var/lib/mcp-gateway-reverse"
declare -r state_dir="$base_dir/$enrollment"
declare -r state_file="$state_dir/enrollment.json"
declare -r keys_dir="$state_dir/ssh"
declare -r control_key="$keys_dir/control"
declare -r unit="/etc/systemd/system/mcp-gateway-reverse-$enrollment.service"
# Use the 60 random ULID bits, not the time-dominated prefix. Concurrent
# enrollments in one millisecond must not share a dedicated OS account.
declare -r client_user="mcp-r-$(printf '%s' "${enrollment:14:12}" | tr '[:upper:]' '[:lower:]')"
declare -r api="${gateway%/}/reverse-ssh/enroll/$enrollment/claim"
# Guard every root-written state parent BEFORE any mkdir, lock redirection,
# key creation or one-use claim. install -d does not take ownership of an
# existing directory; a pre-planted writable directory must never be adopted.
# Only root may own the enrollment and lock directory. The private SSH key
# directory may belong to our verified dedicated tunnel account on a retry.
python3 -I - "$base_dir" "$state_dir" "$keys_dir" "$state_file" "$unit" "$client_user" <<'PYTHON'
import os, pathlib, pwd, stat, sys
base, state, keys, state_file, unit, tunnel_user = sys.argv[1:]
try:
    tunnel_uid = pwd.getpwnam(tunnel_user).pw_uid
except KeyError:
    tunnel_uid = None
for path in (base, state, keys):
    if not os.path.lexists(path):
        continue
    st = os.lstat(path)
    expected = {0} if path != keys else {0} | ({tunnel_uid} if tunnel_uid is not None else set())
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in expected or st.st_mode & 0o022:
        raise SystemExit(f"Unsafe managed directory ownership, mode or type: {path}")
    if path == keys and st.st_mode & 0o077:
        raise SystemExit("Private control key directory must be mode 0700")
for path in (state_file, os.path.join(state, ".install.lock"), unit):
    if not os.path.lexists(path):
        continue
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or (path == state_file and st.st_mode & 0o077):
        raise SystemExit(f"Unsafe root-managed file ownership, mode or type: {path}")
for name in ("control", "control.pub", "known_hosts"):
    path = os.path.join(keys, name)
    if not os.path.lexists(path):
        continue
    st = os.lstat(path)
    allowed = {0} | ({tunnel_uid} if tunnel_uid is not None else set())
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in allowed or st.st_mode & 0o022:
        raise SystemExit(f"Unsafe control key file ownership, mode or type: {path}")
PYTHON
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
# Validate the exact Owner-selected OS login before consuming the one-use
# claim. An absent account or unsafe SSH home must not burn an enrollment.
if [[ -n "$expected_user" && ! -f "$state_file" ]]; then
    getent passwd "$expected_user" >/dev/null ||
        die "The Owner-enrolled SSH login account does not exist."
    expected_home="$(getent passwd "$expected_user" | awk -F: '{print $6}')"
    [[ "$expected_home" = /* && -d "$expected_home" && ! -L "$expected_home" ]] ||
        die "The Owner-enrolled SSH login account has an unsafe home."
    [[ ! -L "$expected_home/.ssh" && ! -L "$expected_home/.ssh/authorized_keys" ]] ||
        die "Symlinked Target login SSH key paths are unsafe."
    [[ ! -e "$expected_home/.ssh/authorized_keys" || -f "$expected_home/.ssh/authorized_keys" ]] ||
        die "Owner-enrolled SSH login authorized_keys is not a regular file."
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
if getent passwd "$client_user" >/dev/null; then
    [[ -f "$control_key" && -f "$control_key.pub" ]] ||
        die "Existing tunnel account lost its control key; Owner reconciliation required."
    if [[ "$(stat -c '%u' "$keys_dir")" == 0 ]]; then
        # Recover a root-owned, previously verified partial claim. Never
        # recursively chown a directory controlled by an unprivileged user.
        chown "$client_user:$client_user" "$keys_dir" "$control_key" "$control_key.pub"
    fi
    runuser -u "$client_user" -- install -d -m 0700 "$keys_dir" ||
        die "Tunnel user cannot access owned private key directory."
    runuser -u "$client_user" -- chmod 0600 "$control_key"
    runuser -u "$client_user" -- chmod 0644 "$control_key.pub"
else
    install -d -m 0700 "$keys_dir"
    if [[ ! -f "$control_key" ]]; then
        ssh-keygen -q -t ed25519 -N '' -f "$control_key" -C "" || die "SSH key creation failed."
    fi
    chmod 0600 "$control_key"
    chmod 0644 "$control_key.pub"
fi
[[ -f "$control_key" && ! -L "$control_key" && -f "$control_key.pub" && ! -L "$control_key.pub" ]] || die "Unexpected tunnel key layout."
# The token never appears in the HTTP URL, access log route, or public artifact.
# Keep claim and bootstrap outcome in ONE root-owned, durably replaced file.
# An old cache without a journal is NOT evidence that login provisioning was
# never attempted. A completed cache no longer carries a login public key.
tmp_request="$state_dir/.request.$$"
tmp_response="$state_dir/.response.$$"
params="$state_dir/.parameters.$$"
cleanup() { rm -f "$tmp_request" "$tmp_response" "$params"; }
trap cleanup EXIT

cache_state() {
    local public_key
    if getent passwd "$client_user" >/dev/null; then
        public_key="$(runuser -u "$client_user" -- head -c 4096 "$control_key.pub")" || return 1
    else
        public_key="$(head -c 4096 "$control_key.pub")" || return 1
    fi
    python3 -I - "$1" "$state_file" "$tmp_response" "$params" "$enrollment" "$gateway" \
        "$owner_pin" "$local_port" "$expected_user" "$public_key" <<'PYTHON'
import hashlib, json, os, pathlib, re, sys, tempfile
action, cache, response, output, enrollment, gateway, pin, port, user, control = sys.argv[1:]
source = response if action == "fresh" else cache
data = json.loads(pathlib.Path(source).read_text())
if data.get("state") != "control_key_activated" or data.get("verified") is not False:
    raise SystemExit("Invalid claimed state")
names = ("control_host", "control_port", "control_user", "control_host_key",
         "listener_port", "target_port", "target_username", "login_public_key")
key_pattern = r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+"
assert re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", data["control_host"])
assert re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", data["control_user"])
assert re.fullmatch(key_pattern, data["control_host_key"])
assert isinstance(data["target_username"], str) and isinstance(data["login_public_key"], str)
if data["login_public_key"]:
    assert user and data["target_username"] == user
    assert re.fullmatch(key_pattern, data["login_public_key"])
else:
    assert data["target_username"] == ""
for name in ("control_port", "listener_port", "target_port"):
    assert type(data[name]) is int and 1 <= data[name] <= 65535
assert data["target_port"] == int(port)
receipt = data.get("bootstrap_receipt")
if action == "fresh":
    assert (isinstance(receipt, str) and bool(receipt)) if data["login_public_key"] else receipt is None
control_hash = hashlib.sha256(" ".join(control.split()[:2]).encode()).hexdigest()
# New responses explicitly bind the exact command and claim. Legacy caches
# can still repair transport; they cannot authorize a new login write.
for name, expected in (("enrollment_id", enrollment), ("control_key_hash", control_hash),
                       ("target_host_key", pin)):
    if action == "fresh" or name in data:
        assert data.get(name) == expected, name

def binding():
    receipt = {k: v for k, v in data.items() if k != "_bootstrap"}
    exact = [enrollment, gateway.rstrip("/"), pin, port, user, control_hash, receipt]
    return hashlib.sha256(json.dumps(exact, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def store(phase):
    data["_bootstrap"] = {"version": 1, "phase": phase, "binding": binding()}
    parent = os.path.dirname(cache)
    fd, tmp = tempfile.mkstemp(prefix=".enrollment-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, cache)
        directory = os.open(parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

journal = data.get("_bootstrap")
if action == "fresh":
    assert journal is None and not os.path.lexists(cache)
    phase = "unattempted" if data["login_public_key"] else "complete"
    store(phase)
elif journal is None:
    assert action == "read"
    phase = "attempted" if data["login_public_key"] else "complete"
    store(phase)
else:
    assert journal["version"] == 1 and journal["binding"] == binding()
    phase = journal["phase"]
    assert phase in ("unattempted", "attempted", "complete", "uncertain")
    assert bool(data["login_public_key"]) == (phase in ("unattempted", "attempted"))
    if phase == "unattempted":
        assert isinstance(receipt, str) and bool(receipt)
    if action == "attempt":
        assert phase == "unattempted"
        phase = "attempted"
        store(phase)
    elif action in ("complete", "uncertain"):
        assert phase in ("unattempted", "attempted")
        phase = action
        data["login_public_key"] = ""
        data["target_username"] = ""
        data.pop("bootstrap_receipt", None)
        store(phase)
    elif action == "check":
        assert phase == "unattempted"
        with open(output, "x", encoding="utf-8") as dest:
            json.dump({"receipt": receipt}, dest)
    else:
        assert action == "read"
if action in ("fresh", "read"):
    with open(output, "x", encoding="utf-8") as dest:
        for name in names:
            dest.write(str(data[name]) + "\n")
        dest.write(phase + "\n")
PYTHON
}

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
    if ! curl --proto '=https' --tlsv1.2 -fsS --connect-timeout 8 --max-time 25 \
        -H 'Content-Type: application/json' -H 'Accept: application/json' \
        --request POST --data-binary "@$tmp_request" --output "$tmp_response" "$api"; then
        die "Gateway claim failed or is uncertain. Do not retry with a new key/token; ask Owner to reconcile."
    fi
    cache_state fresh || die "Invalid Gateway claim response or uncertain cache persistence; reconcile with Owner."
else
    cache_state read || die "Invalid cached enrollment identity or bootstrap evidence; reconcile with Owner."
fi
mapfile -t params_data < "$params"
rm -f "$params" "$tmp_request" "$tmp_response"
control_host="${params_data[0]}" control_port="${params_data[1]}"
control_user="${params_data[2]}" control_host_key="${params_data[3]}"
listener_port="${params_data[4]}" registered_port="${params_data[5]}"
target_user="${params_data[6]}" login_public_key="${params_data[7]}" bootstrap_phase="${params_data[8]}"

# The response is durable BEFORE creating an OS account. Explicit
# --user-group avoids relying on distro-specific USERGROUPS_ENAB defaults.
if ! getent passwd "$client_user" >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir "$state_dir" \
        --shell /usr/sbin/nologin "$client_user" ||
        die "Could not create the dedicated non-root tunnel account."
fi
[[ "$(id -gn "$client_user")" == "$client_user" ]] ||
    die "Dedicated tunnel service group does not match its account."
if [[ "$(stat -c '%u' "$keys_dir")" == 0 ]]; then
    chown "$client_user:$client_user" "$keys_dir" "$control_key" "$control_key.pub"
fi
runuser -u "$client_user" -- chmod 0700 "$keys_dir"

bootstrap_warning() {
    notice "Initial SSH login setup could not be confirmed. Transport recovery does not restore a missing login key. Verify SSH host and login, or request a new authorized setup/credential recovery."
}
# Login-owned paths are never written as root. A read-only reconciliation
# may settle a prior possible write, but may never restore an absent key.
if [[ -n "$login_public_key" ]]; then
    target_home="$(getent passwd "$target_user" | awk -F: '{print $6}' || true)"
    login_ssh="$target_home/.ssh"
    login_keys="$login_ssh/authorized_keys"
    if [[ "$target_home" != /* || ! -d "$target_home" || -L "$target_home" || -L "$login_ssh" || -L "$login_keys" || ( -e "$login_keys" && ! -f "$login_keys" ) ]]; then
        cache_state uncertain || die "Could not settle unavailable login identity."
        bootstrap_warning
    elif runuser -u "$target_user" -- grep -Fxq -- "$login_public_key" "$login_keys" 2>/dev/null; then
        cache_state complete || die "Could not settle existing login key evidence."
    elif [[ "$bootstrap_phase" == "unattempted" ]]; then
        # Even a provably unattempted cache is not fresh remote authority.
        # Recheck the exact initial grant; the old one-use token is never
        # replayed. A temporary failure leaves transport repair available.
        cache_state check || die "Could not prepare current bootstrap check."
        if ! bootstrap_http="$(curl --proto '=https' --tlsv1.2 -sS --connect-timeout 8 --max-time 25 \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            --request POST --data-binary "@$params" --output /dev/null --write-out '%{http_code}' \
            "${api%/claim}/bootstrap-check")"; then
            bootstrap_http=""
        fi
        rm -f "$params"
        if [[ "$bootstrap_http" == "409" ]]; then
            cache_state uncertain || die "Could not retire stale bootstrap authority."
            bootstrap_warning
        elif [[ "$bootstrap_http" != "204" ]]; then
            bootstrap_warning
        else
            # Persist the possible effect BEFORE even mkdir/chmod. Failure or
            # interruption after this point must not be replayed as fresh setup.
            cache_state attempt || die "Could not persist login bootstrap attempt."
            if runuser -u "$target_user" -- python3 - "$login_ssh" "$login_public_key" <<'PYTHON'
import fcntl, os, re, stat, sys
directory, key = sys.argv[1:]
os.makedirs(directory, mode=0o700, exist_ok=True)
parent = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    fd = os.open("authorized_keys", os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
    with os.fdopen(fd, "r+b") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise SystemExit("Unexpected authorized_keys type")
        fcntl.flock(handle, fcntl.LOCK_EX)
        content = handle.read()
        raw = key.encode()
        if raw not in content.splitlines():
            # Do not bypass existing restrictions on the same public key by
            # appending an unrestricted duplicate (including a comment variant).
            algorithm, blob = raw.split()[:2]
            key_pattern = rb"(?:^|\s)" + re.escape(algorithm) + rb"\s+" + re.escape(blob) + rb"(?:\s|$)"
            if any(re.search(key_pattern, line) for line in content.splitlines() if not line.lstrip().startswith(b"#")):
                raise SystemExit("Existing non-exact login key requires operator reconciliation")
            os.fchmod(parent, 0o700)
            os.fchmod(handle.fileno(), 0o600)
            handle.write((b"\n" if content and not content.endswith(b"\n") else b"") + raw + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.fsync(parent)
finally:
    os.close(parent)
home = os.open(os.path.dirname(directory), os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(home)
finally:
    os.close(home)
PYTHON
            then
                cache_state complete || die "Login key may have been written; reconcile before retrying."
            else
                cache_state uncertain || die "Login bootstrap outcome is uncertain; reconcile before retrying."
                bootstrap_warning
            fi
        fi
    else
        cache_state uncertain || die "Could not settle uncertain login bootstrap."
        bootstrap_warning
    fi
elif [[ "$bootstrap_phase" == "uncertain" ]]; then
    bootstrap_warning
fi
# Never write a user-owned known_hosts file as root: a compromised service
# user must not be able to turn an update into a privileged symlink write.
known="$keys_dir/known_hosts"
[[ ! -L "$known" ]] || die "Symlinked known_hosts path refused."
runuser -u "$client_user" -- sh -c '
    umask 077
    printf "[%s]:%s %s\n" "$1" "$2" "$3" > "$4"
' _ "$control_host" "$control_port" "$control_host_key" "$known" ||
    die "Tunnel user cannot write its pinned control host key."
runuser -u "$client_user" -- chmod 0600 "$known" ||
    die "Tunnel user cannot protect its pinned control host key."
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
