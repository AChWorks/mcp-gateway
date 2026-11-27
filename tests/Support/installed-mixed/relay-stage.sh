#!/usr/bin/env bash
# Sourced only by run.sh inside its owned temporary PID/network namespace.
# Reuse the ephemeral OS account, but distinct control host key and public-key
# identity. No changes to the host sshd, systemd, or operator networking.
run_installed_relay() {
  [[ "$(id -u)" == 0 && "$(basename "$ROOT")" == mcp-gateway-installed-112-* &&
      "$MIXED_SSH_USER" =~ ^mcpac[0-9]+$ ]] || {
    echo 'Expected the owned installed mixed namespace.' >&2; return 2;
  }
  local secret="$ROOT/secrets" relay_address=11.22.33.47 relay_port=46257 socks_port=47531
  local control_socket="$secret/relay.sock"
  local relay_home="/home/$MIXED_SSH_USER"
  local authorized="$relay_home/.ssh/mixed-relay-authorized"
  [[ -d "$relay_home" && ! -L "$relay_home/.ssh" && ! -e "$authorized" &&
     ! -L "$authorized" && ! -e "$secret/relay-host" ]] || {
    echo 'Unexpected disposable Relay identity path.' >&2; return 2;
  }
  echo 'Stage: native Relay registration and independently pinned control tunnel'
  ip addr add "$relay_address/32" dev lo
  ssh-keygen -q -t ed25519 -N '' -f "$secret/relay-host"
  awk '{print $1" "$2}' "$secret/relay-host.pub" >"$secret/relay-host.pin"
  chown "$WORKER:$WORKER_GROUP" "$secret/relay-host.pin"
  chmod 600 "$secret/relay-host.pin"
  local -a seed=(runuser -u "$WORKER" -- env MIXED_STATE_FILE="$secret/state.json"
    MIXED_SSH_USER="$MIXED_SSH_USER" MIXED_CALLBACK_FILE="$secret/callback.json"
    php -d "curl.cainfo=$secret/tls.crt" -d "openssl.cafile=$secret/tls.crt"
    "$ROOT/gateway/tests/Support/installed-mixed/seed.php")
  local -a sdk=(runuser -u "$WORKER" -- env MIXED_ROOT="$ROOT" MIXED_SSH_USER="$MIXED_SSH_USER"
    MIXED_SSH_LONG_SECONDS="$MIXED_SSH_LONG_SECONDS" MIXED_SSH_LONG_TIMEOUT="$MIXED_SSH_LONG_TIMEOUT"
    MIXED_SSH_LONG_MODE="$MIXED_SSH_LONG_MODE" MIXED_SSH_LONG_ROUTE="$MIXED_SSH_LONG_ROUTE"
    php "$ROOT/client/client.php")
  "${seed[@]}" relay prepare >"$secret/relay-prepared.json"
  install -d -o "$MIXED_SSH_USER" -g "$(id -gn "$MIXED_SSH_USER")" -m 0700 "$relay_home/.ssh"
  install -o "$MIXED_SSH_USER" -g "$(id -gn "$MIXED_SSH_USER")" -m 0600 \
    "$secret/relay-client.pub" "$authorized"
  cat >"$secret/relay-sshd.conf" <<EOF_RELAY
Port $relay_port
ListenAddress $relay_address
PidFile $secret/relay-sshd.pid
HostKey $secret/relay-host
AuthorizedKeysFile .ssh/mixed-relay-authorized
AllowUsers $MIXED_SSH_USER
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
KbdInteractiveAuthentication no
UsePAM no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
PermitTunnel no
GatewayPorts no
AllowTcpForwarding local
PermitOpen 11.22.33.44:443 11.22.33.46:46231
MaxSessions 0
LogLevel ERROR
EOF_RELAY
  /usr/sbin/sshd -t -f "$secret/relay-sshd.conf"
  /usr/sbin/sshd -D -e -f "$secret/relay-sshd.conf" >"$ROOT/logs/relay-sshd.log" 2>&1 &
  local_pids+=("$!")
  local ready=0
  for _ in {1..30}; do
    if ss -H -lnt "sport = :$relay_port" | grep -Fq "$relay_address:$relay_port"; then
      ready=1; break
    fi
    sleep 0.2
  done
  [[ "$ready" == 1 ]] || { echo 'Native Relay control sshd not ready.' >&2; return 1; }
  local -a native=(runuser -u "$WORKER" -- ssh -F /dev/null -p "$relay_port"
    -i "$secret/relay-client.key" -o IdentitiesOnly=yes -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$secret/relay-known-hosts"
    -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ExitOnForwardFailure=yes
    -S "$control_socket")
  start_relay() {
    "${native[@]}" -M -o ControlPersist=no -fNT -D "127.0.0.1:$socks_port" "$MIXED_SSH_USER@$relay_address"
    ss -H -lnt "sport = :$socks_port" | grep -Fq "127.0.0.1:$socks_port"
    curl --silent --show-error --fail --max-time 9 --cacert "$secret/tls.crt" \
      --noproxy '' --proxy "socks5://127.0.0.1:$socks_port" \
      https://11.22.33.44/.well-known/oauth-protected-resource >/dev/null
  }
  stop_relay() {
    "${native[@]}" -O exit "$MIXED_SSH_USER@$relay_address"
    for _ in {1..30}; do
      if [[ ! -S "$control_socket" && -z "$(ss -H -lnt "sport = :$socks_port")" ]]; then
        return 0
      fi
      sleep 0.1
    done
    echo 'Relay listener did not stop.' >&2; return 1
  }
  start_relay
  "${seed[@]}" relay bind >"$secret/relay-bound.json"
  # The prior grant has been revoked through the actual selected Relay.
  # Verify rejection of its original direct access token before fresh consent.
  "${sdk[@]}" wp-oauth direct-denied >"$secret/relay-old-grant.json"
  python3 - "$secret/relay-old-grant.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1])) == {"http_status": 401}, "Prior grant not revoked"
PY
  echo 'Stage: actual WordPress OAuth reauthorization through registered Relay'
  rm -f -- "$secret/cookies.txt" "$secret/callback.json"
  runuser -u "$WORKER" -- env MIXED_ROOT="$ROOT" \
    php -d "curl.cainfo=$secret/tls.crt" -d "openssl.cafile=$secret/tls.crt" \
    "$ROOT/gateway/tests/Support/installed-mixed/consent.php"
  "${seed[@]}" relay-complete
  "${seed[@]}" relay verify >"$secret/relay-verified.json"
  echo 'Stage: actual installed Relay WordPress/SSH capacity'
  "${sdk[@]}" relay online >"$secret/relay-online.json"
  echo 'Stage: native SOCKS listener outage, direct controls stay reachable'
  stop_relay
  "${sdk[@]}" relay offline >"$secret/relay-offline.json"
  echo 'Stage: restart the exact native Relay and verify recovery'
  start_relay
  "${seed[@]}" relay verify >"$secret/relay-reverified.json"
  "${sdk[@]}" relay recovered >"$secret/relay-recovered.json"
  stop_relay
  "${seed[@]}" relay restore >"$secret/relay-restored.json"
  # An explicit detach permits Direct again and preserves the new grant.
  "${sdk[@]}" wp-oauth routed >"$secret/relay-explicit-direct.json"
  python3 - "$secret" >"$MIXED_EVIDENCE/relay.json" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
names = ["prepared", "bound", "old-grant", "verified", "online", "offline", "reverified", "recovered", "restored", "explicit-direct"]
evidence = {name.replace("-", "_"): json.loads((root / f"relay-{name}.json").read_text()) for name in names}
assert evidence["explicit_direct"]["ok"] is True and evidence["explicit_direct"]["data"]["principal_id"] == 1
evidence["native_control"] = "separate OpenSSH sshd and pinned key; same disposable Unix account and network namespace"
evidence["native_listener_stopped"] = True
print(json.dumps(evidence, indent=2))
PY
}
