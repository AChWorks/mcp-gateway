#!/usr/bin/env bash
# Disposable GitHub-hosted runner: native two-command Relay and systemd proof.
set -Eeuo pipefail
[[ "$GITHUB_ACTIONS" == true && "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]] ||
  { echo 'Disposable GitHub Actions runner required' >&2; exit 2; }
[[ "$(cat /proc/1/comm)" == systemd && -d "$RUNNER_TEMP" ]] ||
  { echo 'Real systemd and runner temp required' >&2; exit 2; }

id="ci-relay-$GITHUB_RUN_ID"
unit="mcp-gateway-relay-$id.service"
root="$RUNNER_TEMP/mcp-gateway-relay-systemd-$GITHUB_RUN_ID"
unit_file="/etc/systemd/system/$unit"
identity_dir="/etc/mcp-gateway-relays/$id"

cleanup() {
  local status=0 pid
  if [[ -f "$root/foreign.pid" ]]; then
    pid="$(cat "$root/foreign.pid")"
    if [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] &&
      tr '\0' ' ' <"/proc/$pid/cmdline" | grep -Fq "$root/foreign-socks.py"; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
  if sudo test -f "$unit_file"; then
    if [[ "$(sudo head -n 1 "$unit_file")" != "# Managed by MCP Gateway Relay $id" ]]; then
      echo 'Refusing cleanup of unexpected systemd unit' >&2
      status=1
    else
      sudo systemctl disable --now "$unit" || status=1
      sudo rm -f -- "$unit_file"
      sudo systemctl daemon-reload || status=1
    fi
  fi
  if sudo test -d "$identity_dir"; then
    sudo rm -f -- "$identity_dir/id_ed25519" "$identity_dir/known_hosts"
    sudo rmdir -- "$identity_dir" || status=1
    sudo rmdir -- /etc/mcp-gateway-relays 2>/dev/null || true
  fi
  if [[ -f "$root/owned-by-test" ]]; then
    if [[ -f .env ]] && grep -Fqx '# Gateway Connection Relay disposable CI fixture' .env; then
      rm -f -- .env
    fi
    rm -rf -- "$root"
  fi
  return "$status"
}

action=run
if [[ $# -gt 0 ]]; then action="$1"; fi
if [[ "$action" == cleanup ]]; then cleanup; exit; fi
[[ "$action" == run ]] || { echo 'Usage: script [run|cleanup]' >&2; exit 2; }
[[ "$SSH_FIXTURE_ROOT" == "$RUNNER_TEMP/mcp-gateway-ssh-fixture-$GITHUB_RUN_ID" ]] ||
  { echo 'Not using the disposable SSH fixture' >&2; exit 2; }
[[ "$SSH_FIXTURE_USER" =~ ^mcpfx[0-9]+$ ]] ||
  { echo 'Unexpected disposable Unix user' >&2; exit 2; }
[[ -s "$SSH_FIXTURE_ROOT/control_host_ed25519.pin" && ! -e "$root" && ! -e .env ]] ||
  { echo 'Fixture missing or conflicting environment present' >&2; exit 2; }
! sudo test -e "$unit_file" && ! sudo test -e "$identity_dir" ||
  { echo 'Existing host resources; refusing overwrite' >&2; exit 2; }
trap cleanup EXIT

mkdir -m 700 -- "$root"
touch "$root/owned-by-test" "$root/gateway.sqlite"
chmod 600 "$root/gateway.sqlite"
app_key="$(php -r 'echo base64_encode(random_bytes(32));')"
cat > .env <<ENV
# Gateway Connection Relay disposable CI fixture
APP_NAME="MCP Relay CI"
APP_ENV=local
APP_KEY=base64:$app_key
APP_DEBUG=false
APP_URL=http://127.0.0.1
DB_CONNECTION=sqlite
DB_DATABASE=$root/gateway.sqlite
CACHE_STORE=file
SESSION_DRIVER=file
LOG_CHANNEL=stderr
ENV
chmod 600 .env
unset app_key
php artisan migrate --force --no-interaction --quiet

export RELAY_CI_ID="$id" RELAY_CI_ROOT="$root"
php -r '
require "vendor/autoload.php";
$app = require "bootstrap/app.php";
$app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$pin = trim(file_get_contents(getenv("SSH_FIXTURE_ROOT")."/control_host_ed25519.pin"));
$relay = \App\Infrastructure\Connectors\Relay\ConnectionRelay::query()->create([
    "relay_id" => getenv("RELAY_CI_ID"), "display_name" => "Disposable CI Relay",
    "control_host" => "127.0.0.1", "control_port" => 46257,
    "control_user" => getenv("SSH_FIXTURE_USER"), "control_host_key" => $pin,
    "local_socks_port" => 47531,
]);
$onboarding = app(\App\Infrastructure\Connectors\Relay\ConnectionRelayOnboarding::class);
$onboarding->prepare($relay);
$commands = $onboarding->commands($relay->fresh());
foreach (["relay", "gateway"] as $host) {
    file_put_contents(getenv("RELAY_CI_ROOT")."/".$host.".sh", "#!/bin/sh\n".$commands[$host]."\n");
}
'
[[ -s "$root/relay.sh" && -s "$root/gateway.sh" ]]
sh -n "$root/relay.sh"; sh -n "$root/gateway.sh"

cat > "$root/foreign-socks.py" <<'PY'
import socket
import sys
port = int(sys.argv[1])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", port))
listener.listen(5)
while True:
    peer, _ = listener.accept()
    with peer:
        try:
            peer.settimeout(1.0)
            if peer.recv(3) == b"\x05\x01\x00":
                peer.sendall(b"\x05\x00")
        except OSError:
            pass
PY

start_foreign() {
  local port="$1"
  python3 -u "$root/foreign-socks.py" "$port" > "$root/foreign.log" 2>&1 &
  printf '%s\n' "$!" > "$root/foreign.pid"
  for _ in {1..40}; do
    if python3 -c 'import socket,sys;s=socket.socket();x=s.connect_ex(("127.0.0.1",int(sys.argv[1])));s.close();sys.exit(0 if x==0 else 1)' "$port"; then
      return 0
    fi
    sleep 0.1
  done
  cat "$root/foreign.log" >&2
  return 1
}
stop_foreign() {
  local pid
  pid="$(cat "$root/foreign.pid")"
  kill "$pid"
  wait "$pid" 2>/dev/null || true
  rm -f -- "$root/foreign.pid"
}
verify_target_banner() {
  python3 - "$1" <<'PY'
import socket
import struct
import sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3) as sock:
    sock.settimeout(4)
    sock.sendall(b"\x05\x01\x00")
    assert sock.recv(2) == b"\x05\x00", "SOCKS5 negotiation failed"
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 46231))
    reply = sock.recv(10)
    assert len(reply) >= 2 and reply[1] == 0, "SOCKS5 CONNECT failed"
    assert sock.recv(128).startswith(b"SSH-2.0"), "No end-Target SSH banner"
print("PASS: Relay SOCKS5 CONNECT to independent OpenSSH Target.")
PY
}

# Foreign SOCKS5 must not be mistaken for the intended new service.
start_foreign 47531
if bash "$root/gateway.sh" > "$root/first-conflict.log" 2>&1; then
  echo 'First install accepted foreign SOCKS listener' >&2; exit 1
fi
grep -Fq 'occupied by a process other than' "$root/first-conflict.log"
[[ ! -e "$unit_file" ]]
kill -0 "$(cat "$root/foreign.pid")"
stop_foreign

# Execute generated command on each local fixture host role.
bash "$root/relay.sh"
bash "$root/gateway.sh"
sudo systemctl is-enabled --quiet "$unit"
sudo systemctl is-active --quiet "$unit"
verify_target_banner 47531
first_pid="$(sudo systemctl show -p MainPID --value "$unit")"
[[ "$first_pid" =~ ^[1-9][0-9]*$ ]]
bash "$root/relay.sh"
bash "$root/gateway.sh"
[[ "$(sudo systemctl show -p MainPID --value "$unit")" == "$first_pid" ]]
verify_target_banner 47531

# Native restart and update to a new saved SOCKS port.
sudo systemctl restart "$unit"
bash "$root/gateway.sh"
verify_target_banner 47531
php -r '
require "vendor/autoload.php";
$app = require "bootstrap/app.php";
$app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
\Illuminate\Support\Facades\DB::table("connection_relays")
    ->where("relay_id", getenv("RELAY_CI_ID"))
    ->update(["local_socks_port" => 47532]);
'
bash "$root/gateway.sh"
verify_target_banner 47532
if python3 -c 'import socket;s=socket.socket();x=s.connect_ex(("127.0.0.1",47531));s.close();exit(0 if x==0 else 1)'; then
  echo 'Old SOCKS port still bound after update' >&2; exit 1
fi

# Existing unit stopped; unrelated SOCKS listener must not be claimed.
sudo systemctl stop "$unit"
start_foreign 47532
if bash "$root/gateway.sh" > "$root/reinstall-conflict.log" 2>&1; then
  echo 'Reinstall accepted foreign SOCKS listener' >&2; exit 1
fi
grep -Fq 'occupied by a process other than' "$root/reinstall-conflict.log"
kill -0 "$(cat "$root/foreign.pid")"
stop_foreign
bash "$root/gateway.sh"
verify_target_banner 47532
sudo systemctl is-enabled --quiet "$unit"
echo 'PASS: two host commands, service ownership, conflicts, idempotency, restart, update.'
