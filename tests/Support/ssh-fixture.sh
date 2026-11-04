#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"
env_file="${2:-}"
root="${SSH_FIXTURE_ROOT:-}"
# If startup aborts BEFORE the final GITHUB_ENV export, the always() cleanup
# still has a deterministic, narrowly scoped disposable runner path.
if [[ "${action}" == "stop" && -z "${root}" && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]]; then
  root="${RUNNER_TEMP:-/tmp}/mcp-gateway-ssh-fixture-${GITHUB_RUN_ID}"
fi

stop_fixture() {
  if [[ -z "${root}" || ! -d "${root}" ]]; then
    return 0
  fi

  # Stop the task-owned reverse client before stopping the isolated daemons.
  # This must never select a process by name or touch another runner's SSH.
  if [[ -f "${root}/reverse-client.pid" ]]; then
    reverse_pid="$(cat "${root}/reverse-client.pid")"
    if [[ "${reverse_pid}" =~ ^[0-9]+$ ]]; then
      kill "${reverse_pid}" 2>/dev/null || true
    fi
  fi

  shopt -s nullglob
  for pidfile in "${root}"/*.pid; do
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ "${pid}" =~ ^[0-9]+$ ]]; then
      sudo kill "${pid}" 2>/dev/null || true
    fi
  done
  shopt -u nullglob

  fixture_user=""
  if [[ -f "${root}/fixture-user" ]]; then
    fixture_user="$(cat "${root}/fixture-user")"
  fi
  # The elevated SFTP-only fixture grants a temporary scoped sudo command.
  # Remove its grant before deleting the associated disposable OS account.
  if [[ "${fixture_user}" =~ ^mcpfx[0-9]+$ ]]; then
    sudo rm -f "/etc/sudoers.d/ach-mcp-sftp-${fixture_user}"
  fi
  if [[ -n "${fixture_user}" ]] && id "${fixture_user}" >/dev/null 2>&1; then
    sudo userdel -r "${fixture_user}" >/dev/null 2>&1 || true
  fi

  rm -rf "${root}"
}

if [[ "${action}" == "stop" ]]; then
  stop_fixture
  exit 0
fi

if [[ "${action}" != "start" ]]; then
  echo "Usage: bash tests/Support/ssh-fixture.sh start <github-env-file> | stop" >&2
  exit 2
fi

command -v sshd >/dev/null 2>&1 || {
  echo "sshd is required for the disposable SSH fixture." >&2
  exit 2
}
command -v ssh-keygen >/dev/null 2>&1 || {
  echo "ssh-keygen is required for the disposable SSH fixture." >&2
  exit 2
}

run_id="${GITHUB_RUN_ID:-$$}"
fixture_user="mcpfx${run_id}"
fixture_user="${fixture_user:0:30}"
root="${RUNNER_TEMP:-/tmp}/mcp-gateway-ssh-fixture-${run_id}"
password='GatewaySshFixture!234'
key_passphrase='fixture-key-passphrase'
ports=(46231 46232 46233 46234 46235 46236 46237 46238 46239 46240 46241 46242 46243)

if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  printf '::add-mask::%s\n' "${password}"
  printf '::add-mask::%s\n' "${key_passphrase}"
fi

if [[ -e "${root}" ]]; then
  echo "Refusing to reuse an existing SSH fixture root: ${root}" >&2
  exit 1
fi
if id "${fixture_user}" >/dev/null 2>&1; then
  echo "Refusing to reuse an existing SSH fixture user: ${fixture_user}" >&2
  exit 1
fi

mkdir -p "${root}"
printf '%s' "${fixture_user}" > "${root}/fixture-user"
sudo mkdir -p /run/sshd
sudo useradd -m -s /bin/bash "${fixture_user}"
# Existing restricted staging directory is provisioned by the fixture, not
# created through the library's permissive SFTP MKDIR implementation.
sudo install -d -m 700 -o "${fixture_user}" -g "${fixture_user}" "/home/${fixture_user}/.mcp-stream-private"
sudo install -d -m 700 -o "${fixture_user}" -g "${fixture_user}" "/home/${fixture_user}/.mcp-stream-watch-private"
sudo install -d -m 700 -o "${fixture_user}" -g "${fixture_user}" "/home/${fixture_user}/.mcp-stream-elevated-private"
sudo install -d -m 755 -o "${fixture_user}" -g "${fixture_user}" "/home/${fixture_user}/.mcp-stream-insecure"
sudo install -d -m 700 -o root -g root "/home/${fixture_user}/.mcp-stream-foreign"
sudo ln -s "/home/${fixture_user}/.mcp-stream-private" "/home/${fixture_user}/.mcp-stream-symlink"
# Only the ephemeral fixture OS account may launch the stock sftp-server as
# root, and only on the GitHub runner. No sudo shell, arbitrary command,
# production credential or persistent service is granted.
sudoers="/etc/sudoers.d/ach-mcp-sftp-${fixture_user}"
printf '%s ALL=(root) NOPASSWD: /usr/lib/openssh/sftp-server\n' "${fixture_user}" | sudo tee "${sudoers}" >/dev/null
sudo chmod 0440 "${sudoers}"
sudo visudo -cf "${sudoers}" >/dev/null

printf '%s:%s\n' "${fixture_user}" "${password}" | sudo chpasswd

ssh-keygen -q -t ed25519 -N '' -f "${root}/host_ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "${root}/host_rsa"
# Separate cryptographic control-channel sshd identity (not the end Target).
ssh-keygen -q -t ed25519 -N '' -f "${root}/control_host_ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "${root}/control_host_rsa"
ssh-keygen -q -t ed25519 -N '' -f "${root}/wrong_ed25519"
ssh-keygen -q -t rsa -b 3072 -N "${key_passphrase}" -f "${root}/login_rsa"
# Disposable no-pass key only for the restricted remote-forward control login.
ssh-keygen -q -t ed25519 -N '' -f "${root}/reverse_tunnel_key"
# Separate client principal for -D (neither Target login nor Reverse).
ssh-keygen -q -t ed25519 -N '' -f "${root}/relay_control_key"

# Registration intentionally accepts only the canonical two-field public-key
# form. ssh-keygen appends a local comment by default, so strip fixture-only
# comments rather than weakening the production parser.
awk '{print $1" "$2}' "${root}/host_ed25519.pub" > "${root}/host_ed25519.pin"
awk '{print $1" "$2}' "${root}/control_host_ed25519.pub" > "${root}/control_host_ed25519.pin"
! cmp -s "${root}/host_ed25519.pin" "${root}/control_host_ed25519.pin"
awk '{print $1" "$2}' "${root}/host_rsa.pub" > "${root}/host_rsa.pin"
awk '{print $1" "$2}' "${root}/wrong_ed25519.pub" > "${root}/wrong_ed25519.pin"

sudo install -d -m 700 -o "${fixture_user}" -g "${fixture_user}" "/home/${fixture_user}/.ssh"
sudo install -m 600 -o "${fixture_user}" -g "${fixture_user}"   "${root}/login_rsa.pub" "/home/${fixture_user}/.ssh/authorized_keys"
awk '{print "restrict,port-forwarding,permitlisten=\"127.0.0.1:46250\" "$1" "$2}' "${root}/reverse_tunnel_key.pub" | sudo tee -a "/home/${fixture_user}/.ssh/authorized_keys" >/dev/null
# Only this dedicated relay key can authenticate to relay-control sshd.
awk '{print "restrict,port-forwarding,permitopen=\"127.0.0.1:46231\",permitopen=\"[::1]:46231\",permitopen=\"127.0.0.1:46244\" "$1" "$2}' "${root}/relay_control_key.pub" |
  sudo tee "/home/${fixture_user}/.ssh/relay_authorized_keys" >/dev/null
sudo chown "${fixture_user}:${fixture_user}" "/home/${fixture_user}/.ssh/relay_authorized_keys"
sudo chmod 600 "/home/${fixture_user}/.ssh/relay_authorized_keys"

start_daemon() {
  local name="$1"
  local port="$2"
  shift 2
  local config="${root}/sshd-${name}.conf"
  local log="${root}/sshd-${name}.log"
  local pidfile="${root}/sshd-${name}.pid"

  local allow_forwarding=no
  local allow_password=yes
  local host_key_prefix=host
  local keys_file=.ssh/authorized_keys
  if [[ "${name}" == "reverse-control" ]]; then
    allow_forwarding=remote
    allow_password=no
    host_key_prefix=control_host
  elif [[ "${name}" == "relay-control" ]]; then
    allow_forwarding=local
    allow_password=no
    host_key_prefix=control_host
    keys_file=.ssh/relay_authorized_keys
  fi
  cat > "${config}" <<EOF_CONFIG
Port ${port}
ListenAddress 127.0.0.1
PidFile ${pidfile}
HostKey ${root}/${host_key_prefix}_ed25519
HostKey ${root}/${host_key_prefix}_rsa
AuthorizedKeysFile ${keys_file}
PasswordAuthentication ${allow_password}
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
AllowUsers ${fixture_user}
AllowAgentForwarding no
AllowTcpForwarding ${allow_forwarding}
GatewayPorts no
PermitTunnel no
X11Forwarding no
LoginGraceTime 15
MaxAuthTries 3
LogLevel VERBOSE
EOF_CONFIG

  for line in "$@"; do
    printf '%s\n' "${line}" >> "${config}"
  done

  : > "${log}"
  sudo chown "${USER}" "${log}"
  sudo /usr/sbin/sshd -f "${config}" -E "${log}"

  for _ in $(seq 1 50); do
    if [[ -s "${pidfile}" ]] && sudo kill -0 "$(cat "${pidfile}")" 2>/dev/null; then
      if timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
        return 0
      fi
    fi
    sleep 0.1
  done

  cat "${log}" >&2 || true
  echo "SSH fixture ${name} failed to start on port ${port}." >&2
  exit 1
}

sudo install -m 755 -o root -g root "tests/Support/sftp-hostile-fixture.py" "/home/${fixture_user}/.mcp-hostile-sftp.py"
start_daemon modern "${ports[0]}" "ListenAddress ::1" "Subsystem sftp internal-sftp"
start_daemon legacy-rsa "${ports[1]}"   "HostKeyAlgorithms ssh-rsa"   "KexAlgorithms curve25519-sha256"   "Ciphers aes128-ctr"   "MACs hmac-sha2-256"
start_daemon weak-kex "${ports[2]}"   "HostKeyAlgorithms ssh-ed25519"   "KexAlgorithms diffie-hellman-group14-sha1"   "Ciphers aes128-ctr"   "MACs hmac-sha2-256"
start_daemon weak-cipher "${ports[3]}"   "HostKeyAlgorithms ssh-ed25519"   "KexAlgorithms curve25519-sha256"   "Ciphers aes128-cbc"   "MACs hmac-sha2-256"
start_daemon weak-mac "${ports[4]}"   "HostKeyAlgorithms ssh-ed25519"   "KexAlgorithms curve25519-sha256"   "Ciphers aes128-ctr"   "MACs hmac-sha1"
# Intentionally no Subsystem sftp: library must not fall back to shell exec.
start_daemon no-sftp "${ports[5]}"
# Controlled malicious SFTP endpoints for boundary tests; only loopback.
start_daemon oversize "${ports[6]}" "Subsystem sftp /usr/bin/python3 /home/${fixture_user}/.mcp-hostile-sftp.py oversize"
start_daemon delay-write "${ports[7]}" "Subsystem sftp /usr/bin/python3 /home/${fixture_user}/.mcp-hostile-sftp.py delay-write"
start_daemon unexpected-ids "${ports[8]}" "Subsystem sftp /usr/bin/python3 /home/${fixture_user}/.mcp-hostile-sftp.py unexpected-ids"
start_daemon watch-first-write "${ports[9]}" "Subsystem sftp /usr/bin/python3 /home/${fixture_user}/.mcp-hostile-sftp.py watch-first-write"
start_daemon elevated-sftp "${ports[10]}" "Subsystem sftp /usr/bin/sudo -n /usr/lib/openssh/sftp-server"
start_daemon reverse-control "${ports[11]}" \
  "PermitListen 127.0.0.1:46250" "PermitOpen none" "PermitTTY no" "ForceCommand /bin/false" "AllowStreamLocalForwarding no"
start_daemon relay-control "${ports[12]}" \
  "PermitOpen 127.0.0.1:46231 [::1]:46231 127.0.0.1:46244" "PermitListen none" "PermitTTY no" "ForceCommand /bin/false" "AllowStreamLocalForwarding no"
# Client-initiated OpenSSH -R: listener and actual pinned end-host sshd
# remain separate SSH authentication and trust domains.
printf '[127.0.0.1]:%s %s\n' "${ports[11]}" "$(cat "${root}/control_host_ed25519.pin")" > "${root}/reverse_known_hosts"
chmod 600 "${root}/reverse_known_hosts"
ssh -NT -p "${ports[11]}" -i "${root}/reverse_tunnel_key" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="${root}/reverse_known_hosts" \
  -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
  -R "127.0.0.1:46250:127.0.0.1:${ports[0]}" \
  "${fixture_user}@127.0.0.1" > "${root}/reverse-client.log" 2>&1 &
reverse_pid="$!"
printf '%s\n' "${reverse_pid}" > "${root}/reverse-client.pid"
for _ in $(seq 1 50); do
  if ! kill -0 "${reverse_pid}" 2>/dev/null; then
    cat "${root}/reverse-client.log" >&2
    echo 'OpenSSH -R client exited before opening the local fixture listener.' >&2
    exit 1
  fi
  if timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/46250' 2>/dev/null; then
    break
  fi
  sleep 0.1
done
timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/46250' 2>/dev/null || {
  cat "${root}/reverse-client.log" >&2
  echo 'OpenSSH -R fixture listener failed to start.' >&2
  exit 1
}

# Disposable TLS end host for real Guzzle/SNI/certificate forwarding.
# The restricted Relay control permits only this HTTPS fixture port in
# addition to the actual SSH Target port, never arbitrary public egress.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=wp.fixture.test' -addext 'subjectAltName=DNS:wp.fixture.test' \
  -keyout "${root}/relay-tls.key" -out "${root}/relay-tls.crt" > /dev/null 2>&1
openssl s_server -accept 127.0.0.1:46244 -cert "${root}/relay-tls.crt" \
  -key "${root}/relay-tls.key" -www > "${root}/relay-tls.log" 2>&1 &
printf '%s\n' "$!" > "${root}/relay-tls.pid"
for _ in $(seq 1 50); do
  if timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/46244' 2>/dev/null; then
    break
  fi
  sleep 0.1
done
timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/46244' 2>/dev/null || {
  echo 'Disposable HTTPS fixture did not start.' >&2
  exit 1
}

# Distinct restricted local dynamic -D route. The CI OpenSSH daemon
# admits only the dedicated key, only the approved loopback Target port,
# and never permits a shell session.
printf '[127.0.0.1]:%s %s\n' "${ports[12]}" "$(cat "${root}/control_host_ed25519.pin")" > "${root}/relay_known_hosts"
chmod 600 "${root}/relay_known_hosts"
ssh -NT -p "${ports[12]}" -i "${root}/relay_control_key" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="${root}/relay_known_hosts" \
  -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
  -D "127.0.0.1:46251" "${fixture_user}@127.0.0.1" > "${root}/relay-client.log" 2>&1 &
relay_pid="$!"
printf '%s\n' "${relay_pid}" > "${root}/relay-client.pid"
for _ in $(seq 1 50); do
  if ! kill -0 "${relay_pid}" 2>/dev/null; then
    cat "${root}/relay-client.log" >&2
    echo 'OpenSSH -D client unexpectedly exited.' >&2
    exit 1
  fi
  if timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/46251' 2>/dev/null; then
    break
  fi
  sleep 0.1
done
timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/46251' 2>/dev/null || {
  cat "${root}/relay-client.log" >&2
  echo 'OpenSSH -D listener failed to start.' >&2
  exit 1
}

# A tunnel-control key must NOT provide a shell or execute even a
# noninteractive command; -N/-R works without asking sshd for a session.
if ssh -T -p "${ports[11]}" -i "${root}/reverse_tunnel_key" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="${root}/reverse_known_hosts" \
  "${fixture_user}@127.0.0.1" 'printf REVERSE_CONTROL_EXEC_DENIED_PROOF' \
  > "${root}/reverse-command-probe.log" 2>&1; then
  echo 'The restricted remote-forward identity unexpectedly executed a command.' >&2
  exit 1
fi
if grep -Fq 'REVERSE_CONTROL_EXEC_DENIED_PROOF' "${root}/reverse-command-probe.log"; then
  echo 'The restricted tunnel key exposed remote shell/exec output.' >&2
  exit 1
fi

if [[ -n "${env_file}" ]]; then
  cat >> "${env_file}" <<EOF_ENV
SSH_FIXTURE_ENABLED=1
SSH_FIXTURE_ROOT=${root}
SSH_FIXTURE_USER=${fixture_user}
SSH_FIXTURE_PASSWORD=${password}
SSH_FIXTURE_KEY_PASSPHRASE=${key_passphrase}
SSH_FIXTURE_RSA_LOGIN_KEY=${root}/login_rsa
SSH_FIXTURE_ED25519_HOST_PUB=${root}/host_ed25519.pin
SSH_FIXTURE_RSA_HOST_PUB=${root}/host_rsa.pin
SSH_FIXTURE_WRONG_ED25519_HOST_PUB=${root}/wrong_ed25519.pin
SSH_FIXTURE_PRIVATE_STAGING=/home/${fixture_user}/.mcp-stream-private
SSH_FIXTURE_WATCH_PRIVATE_STAGING=/home/${fixture_user}/.mcp-stream-watch-private
SSH_FIXTURE_ELEVATED_PRIVATE_STAGING=/home/${fixture_user}/.mcp-stream-elevated-private
SSH_FIXTURE_INSECURE_STAGING=/home/${fixture_user}/.mcp-stream-insecure
SSH_FIXTURE_FOREIGN_STAGING=/home/${fixture_user}/.mcp-stream-foreign
SSH_FIXTURE_SYMLINK_STAGING=/home/${fixture_user}/.mcp-stream-symlink
SSH_FIXTURE_MISSING_STAGING=/home/${fixture_user}/.mcp-stream-missing
SSH_FIXTURE_PORT_MODERN=${ports[0]}
SSH_FIXTURE_REVERSE_PORT=46250
SSH_FIXTURE_REVERSE_CONTROL_PORT=${ports[11]}
SSH_FIXTURE_RELAY_SOCKS_PORT=46251
SSH_FIXTURE_RELAY_CONTROL_PORT=${ports[12]}
SSH_FIXTURE_RELAY_TLS_CERT=${root}/relay-tls.crt
SSH_FIXTURE_RELAY_TLS_PORT=46244
SSH_FIXTURE_RELAY_TLS_HOST=wp.fixture.test
SSH_FIXTURE_REVERSE_CONTROL_HOST_PUB=${root}/control_host_ed25519.pin
SSH_FIXTURE_PORT_LEGACY_RSA=${ports[1]}
SSH_FIXTURE_PORT_WEAK_KEX=${ports[2]}
SSH_FIXTURE_PORT_WEAK_CIPHER=${ports[3]}
SSH_FIXTURE_PORT_WEAK_MAC=${ports[4]}
SSH_FIXTURE_PORT_NO_SFTP=${ports[5]}
SSH_FIXTURE_PORT_OVERSIZE=${ports[6]}
SSH_FIXTURE_PORT_DELAY_WRITE=${ports[7]}
SSH_FIXTURE_PORT_UNEXPECTED_IDS=${ports[8]}
SSH_FIXTURE_PORT_WATCH_FIRST_WRITE=${ports[9]}
SSH_FIXTURE_PORT_ELEVATED_SFTP=${ports[10]}
SSH_FIXTURE_LOG_MODERN=${root}/sshd-modern.log
SSH_FIXTURE_LOG_LEGACY_RSA=${root}/sshd-legacy-rsa.log
SSH_FIXTURE_LOG_WEAK_KEX=${root}/sshd-weak-kex.log
SSH_FIXTURE_LOG_WEAK_CIPHER=${root}/sshd-weak-cipher.log
SSH_FIXTURE_LOG_WEAK_MAC=${root}/sshd-weak-mac.log
EOF_ENV
fi

printf 'Disposable OpenSSH fixture ready on loopback only.\n'
