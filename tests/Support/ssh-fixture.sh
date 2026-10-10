#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"
env_file="${2:-}"
root="${SSH_FIXTURE_ROOT:-}"

stop_fixture() {
  if [[ -z "${root}" || ! -d "${root}" ]]; then
    return 0
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
ports=(46231 46232 46233 46234 46235)

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
printf '%s:%s\n' "${fixture_user}" "${password}" | sudo chpasswd

ssh-keygen -q -t ed25519 -N '' -f "${root}/host_ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "${root}/host_rsa"
ssh-keygen -q -t ed25519 -N '' -f "${root}/wrong_ed25519"
ssh-keygen -q -t rsa -b 3072 -N "${key_passphrase}" -f "${root}/login_rsa"

# Registration intentionally accepts only the canonical two-field public-key
# form. ssh-keygen appends a local comment by default, so strip fixture-only
# comments rather than weakening the production parser.
awk '{print $1" "$2}' "${root}/host_ed25519.pub" > "${root}/host_ed25519.pin"
awk '{print $1" "$2}' "${root}/host_rsa.pub" > "${root}/host_rsa.pin"
awk '{print $1" "$2}' "${root}/wrong_ed25519.pub" > "${root}/wrong_ed25519.pin"

sudo install -d -m 700 -o "${fixture_user}" -g "${fixture_user}" "/home/${fixture_user}/.ssh"
sudo install -m 600 -o "${fixture_user}" -g "${fixture_user}"   "${root}/login_rsa.pub" "/home/${fixture_user}/.ssh/authorized_keys"

start_daemon() {
  local name="$1"
  local port="$2"
  shift 2
  local config="${root}/sshd-${name}.conf"
  local log="${root}/sshd-${name}.log"
  local pidfile="${root}/sshd-${name}.pid"

  cat > "${config}" <<EOF_CONFIG
Port ${port}
ListenAddress 127.0.0.1
PidFile ${pidfile}
HostKey ${root}/host_ed25519
HostKey ${root}/host_rsa
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
AllowUsers ${fixture_user}
AllowAgentForwarding no
AllowTcpForwarding no
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

start_daemon modern "${ports[0]}"
start_daemon legacy-rsa "${ports[1]}"   "HostKeyAlgorithms ssh-rsa"   "KexAlgorithms curve25519-sha256"   "Ciphers aes128-ctr"   "MACs hmac-sha2-256"
start_daemon weak-kex "${ports[2]}"   "HostKeyAlgorithms ssh-ed25519"   "KexAlgorithms diffie-hellman-group14-sha1"   "Ciphers aes128-ctr"   "MACs hmac-sha2-256"
start_daemon weak-cipher "${ports[3]}"   "HostKeyAlgorithms ssh-ed25519"   "KexAlgorithms curve25519-sha256"   "Ciphers aes128-cbc"   "MACs hmac-sha2-256"
start_daemon weak-mac "${ports[4]}"   "HostKeyAlgorithms ssh-ed25519"   "KexAlgorithms curve25519-sha256"   "Ciphers aes128-ctr"   "MACs hmac-sha1"

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
SSH_FIXTURE_PORT_MODERN=${ports[0]}
SSH_FIXTURE_PORT_LEGACY_RSA=${ports[1]}
SSH_FIXTURE_PORT_WEAK_KEX=${ports[2]}
SSH_FIXTURE_PORT_WEAK_CIPHER=${ports[3]}
SSH_FIXTURE_PORT_WEAK_MAC=${ports[4]}
SSH_FIXTURE_LOG_MODERN=${root}/sshd-modern.log
SSH_FIXTURE_LOG_LEGACY_RSA=${root}/sshd-legacy-rsa.log
SSH_FIXTURE_LOG_WEAK_KEX=${root}/sshd-weak-kex.log
SSH_FIXTURE_LOG_WEAK_CIPHER=${root}/sshd-weak-cipher.log
SSH_FIXTURE_LOG_WEAK_MAC=${root}/sshd-weak-mac.log
EOF_ENV
fi

printf 'Disposable OpenSSH fixture ready on loopback only.\n'
