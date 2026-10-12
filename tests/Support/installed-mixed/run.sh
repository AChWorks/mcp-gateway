#!/usr/bin/env bash
# Disposal boundary: one temporary Unix user, local socket MariaDB and a private netns.
set -Eeuo pipefail
SOURCE="$(cd "$(dirname "$0")/../../.." && pwd)"
EVIDENCE_BASE="${MIXED_EVIDENCE_DIR:-/srv/ai-workspace/mcp-gateway-acceptance-20261012}"
WP_ARCHIVE="${MIXED_WORDPRESS_ARCHIVE:-/srv/ai-workspace/wpai-r004-agent-runtime/downloads/wordpress-6.9.tar.gz}"
WP_CLI="${MIXED_WP_CLI_PHAR:-/srv/ai-workspace/wpai-r004-agent-runtime/downloads/wp-cli.phar}"
WP_BRIDGE_ARCHIVE="${MIXED_WP_BRIDGE_ARCHIVE:-/srv/ai-workspace/mcp-gateway-acceptance-20261012/inputs/wp-ai-bridge-0.5.1.zip}"
WP_ADAPTER_ARCHIVE="${MIXED_MCP_ADAPTER_ARCHIVE:-/srv/ai-workspace/wpai-r004-agent-runtime/downloads/mcp-adapter-0.7.0.zip}"
# Released v0.5.1 remains the default. An exact-source Bridge main lane is
# explicitly opt-in and separately pinned; it is NOT a public Bridge release.
MIXED_BRIDGE_PROFILE="${MIXED_BRIDGE_PROFILE:-released-0.5.1}"
case "$MIXED_BRIDGE_PROFILE" in
  released-0.5.1)
    PINS="$SOURCE/tests/Support/installed-mixed/fixture-pins.sha256"
    BRIDGE_PIN_NAME=wp-ai-bridge-0.5.1.zip
    ;;
  merged-main-c522ae9)
    PINS="$SOURCE/tests/Support/installed-mixed/fixture-pins-bridge-main-c522ae9.sha256"
    BRIDGE_PIN_NAME=wp-ai-bridge-main-c522ae9.zip
    ;;
  *)
    echo "Unsupported Bridge source fixture profile." >&2; exit 2
    ;;
esac

# Pinned artifacts are explicitly sourced from upstream release distributions,
# not mutable directories of an already installed WordPress site.
verify_input() {
  local label="$1" path="$2" expected actual
  [[ -f "$path" && -r "$path" && ! -L "$path" ]] || {
    echo "Pinned fixture input is missing, unreadable or a symlink: $label" >&2; return 2;
  }
  expected="$(awk -v label="$label" '$2 == label {print $1}' "$PINS")"
  [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || {
    echo "Fixture pin manifest has an absent/duplicate/invalid digest: $label" >&2; return 2;
  }
  actual="$(sha256sum -- "$path" | cut -d' ' -f1)"
  [[ "$expected" == "$actual" ]] || {
    echo "Fixture digest mismatch (fail closed): $label" >&2; return 2;
  }
}

if [[ "$(id -u)" -ne 0 ]]; then echo "Disposable runner requires root for unshare/sshd." >&2; exit 2; fi
if [[ "${1:-}" == inside ]]; then
  ROOT="$2"
  source "$ROOT/secrets/fixture-env"
  cd "$ROOT"
  ip link set lo up
  for ip in 11.22.33.44 11.22.33.45 11.22.33.46; do ip addr add "$ip/32" dev lo; done
  local_pids=()
  finish_netns() {
    for pid in "${local_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${local_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  }
  trap finish_netns EXIT
  runuser -u aiworker -- env PHP_CLI_SERVER_WORKERS=3 php -d curl.cainfo="$ROOT/secrets/tls.crt" \
    -d openssl.cafile="$ROOT/secrets/tls.crt" -S 127.0.0.1:53801 \
    -t "$ROOT/wp" "$ROOT/wp/router.php" >"$ROOT/logs/wp-http.log" 2>&1 &
  local_pids+=("$!")
  runuser -u aiworker -- env PHP_CLI_SERVER_WORKERS=3 php -d curl.cainfo="$ROOT/secrets/tls.crt" \
    -d openssl.cafile="$ROOT/secrets/tls.crt" -S 127.0.0.1:53802 \
    -t "$ROOT/gateway/public" "$ROOT/gateway/public/index.php" >"$ROOT/logs/gateway-http.log" 2>&1 &
  local_pids+=("$!")
  socat "OPENSSL-LISTEN:443,bind=11.22.33.44,reuseaddr,fork,cert=$ROOT/secrets/tls.pem,verify=0" \
    "TCP:127.0.0.1:53801" >"$ROOT/logs/wp-tls.log" 2>&1 &
  local_pids+=("$!")
  socat "OPENSSL-LISTEN:443,bind=11.22.33.45,reuseaddr,fork,cert=$ROOT/secrets/tls.pem,verify=0" \
    "TCP:127.0.0.1:53802" >"$ROOT/logs/gateway-tls.log" 2>&1 &
  local_pids+=("$!")
  /usr/sbin/sshd -D -e -f "$ROOT/secrets/sshd.conf" >"$ROOT/logs/sshd.log" 2>&1 &
  local_pids+=("$!")
  ready=0
  for count in $(seq 1 30); do
    if curl --noproxy '*' --fail --silent --cacert "$ROOT/secrets/tls.crt" \
        "https://11.22.33.45/up" >/dev/null &&
       curl --noproxy '*' --fail --silent --cacert "$ROOT/secrets/tls.crt" \
        "https://11.22.33.44/.well-known/oauth-protected-resource" >/dev/null &&
       timeout 1 bash -c 'echo > /dev/tcp/11.22.33.46/46231' 2>/dev/null; then
      ready=1; break
    fi
    sleep 0.2
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "Network fixture HTTPS/SSH readiness failed: component status:" >&2
    for endpoint in 11.22.33.45/up 11.22.33.44/.well-known/oauth-protected-resource; do
      printf '%s status: ' "$endpoint" >&2
      curl --noproxy '*' --silent --show-error --max-time 4 \
        --cacert "$ROOT/secrets/tls.crt" -o /dev/null \
        -w '%{http_code}\n' "https://$endpoint" >&2 || true
    done
    printf 'SSH port: ' >&2
    timeout 2 bash -c 'echo > /dev/tcp/11.22.33.46/46231' 2>/dev/null && echo ready >&2 || echo missing >&2
    for log in wp-http wp-tls gateway-http gateway-tls sshd; do
      echo "$log: last request diagnostics" >&2
      tail -n 9 "$ROOT/logs/$log.log" >&2 || true
    done
    exit 1
  fi
  echo "PASS verified HTTPS Gateway health, installed WordPress Bridge metadata and real sshd."
  echo "WordPress public metadata preflight status and redirect (non-sensitive):"
  curl --noproxy '*' --silent --show-error --cacert "$ROOT/secrets/tls.crt" \
    -D - -o /dev/null "https://11.22.33.44/.well-known/oauth-protected-resource" \
    | grep -Ei '^(HTTP/|location:|content-type:)' || true
  cd "$ROOT/gateway"
  runuser -u aiworker -- php -d curl.cainfo="$ROOT/secrets/tls.crt" \
    -d openssl.cafile="$ROOT/secrets/tls.crt" tests/Support/installed-mixed/probe.php
  runuser -u aiworker -- env MIXED_STATE_FILE="$ROOT/secrets/state.json" MIXED_SSH_USER="$MIXED_SSH_USER" \
    MIXED_SSH_HOST_PUB="$ROOT/secrets/ssh_host.pin" MIXED_SSH_PASSWORD_FILE="$ROOT/secrets/ssh-password" \
    php -d curl.cainfo="$ROOT/secrets/tls.crt" -d openssl.cafile="$ROOT/secrets/tls.crt" \
    tests/Support/installed-mixed/seed.php init
  runuser -u aiworker -- env MIXED_ROOT="$ROOT" \
    php -d curl.cainfo="$ROOT/secrets/tls.crt" -d openssl.cafile="$ROOT/secrets/tls.crt" \
    tests/Support/installed-mixed/consent.php
  runuser -u aiworker -- env MIXED_STATE_FILE="$ROOT/secrets/state.json" MIXED_CALLBACK_FILE="$ROOT/secrets/callback.json" \
    php -d curl.cainfo="$ROOT/secrets/tls.crt" -d openssl.cafile="$ROOT/secrets/tls.crt" \
    tests/Support/installed-mixed/seed.php complete
  runuser -u aiworker -- env MIXED_STATE_FILE="$ROOT/secrets/state.json" \
    php -d curl.cainfo="$ROOT/secrets/tls.crt" -d openssl.cafile="$ROOT/secrets/tls.crt" tests/Support/installed-mixed/seed.php diagnose
  runuser -u aiworker -- env MIXED_STATE_FILE="$ROOT/secrets/state.json" \
    php tests/Support/installed-mixed/seed.php report >"$MIXED_EVIDENCE/report.json"
  runuser -u aiworker -- env MIXED_BRIDGE_PROFILE="$MIXED_BRIDGE_PROFILE" MIXED_ROOT="$ROOT" MIXED_SSH_USER="$MIXED_SSH_USER" \
    php "$ROOT/client/client.php" positive >"$MIXED_EVIDENCE/client.json"
  runuser -u aiworker -- env MIXED_ROOT="$ROOT" MIXED_SSH_USER="$MIXED_SSH_USER" \
    php "$ROOT/client/file-client.php" >"$MIXED_EVIDENCE/file-client.json"
  runuser -u aiworker -- env MIXED_ROOT="$ROOT" MIXED_SSH_USER="$MIXED_SSH_USER" \
    python3 "$ROOT/client/file-client.py" >"$MIXED_EVIDENCE/python-file-client.json"
  runuser -u aiworker -- env MIXED_STATE_FILE="$ROOT/secrets/state.json" \
    php tests/Support/installed-mixed/seed.php disable
  runuser -u aiworker -- env MIXED_ROOT="$ROOT" \
    php "$ROOT/client/client.php" revoked >"$MIXED_EVIDENCE/revoked.txt"
  runuser -u aiworker -- env MIXED_ROOT="$ROOT" MIXED_SSH_USER="$MIXED_SSH_USER" \
    php "$ROOT/client/file-client.php" revoked >"$MIXED_EVIDENCE/file-revoked.txt"
  echo "PASS installed WordPress and OpenSSH share one Gateway through a real external MCP SDK client."
  exit 0
fi
# Root orchestration: every network-facing component is launched only by "inside"
# within an independent temporary network namespace.
# Fail closed rather than reporting HEAD/tree for an uncommitted runtime.
if [[ -n "$(GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$SOURCE" -C "$SOURCE" status --porcelain --untracked-files=all)" ]]; then
  echo "Acceptance requires a clean committed candidate (source identity must be exact)." >&2
  exit 2
fi
# Validate every input before allocating test users, databases or listeners.
verify_input wordpress-6.9.tar.gz "$WP_ARCHIVE"
verify_input wp-cli-2.12.0.phar "$WP_CLI"
verify_input "$BRIDGE_PIN_NAME" "$WP_BRIDGE_ARCHIVE"
verify_input mcp-adapter-0.7.0.zip "$WP_ADAPTER_ARCHIVE"
mkdir -p "$EVIDENCE_BASE"
ROOT="$(mktemp -d /srv/ai-workspace/mcp-gateway-installed-112-XXXXXX)"
EVIDENCE="$(mktemp -d "$EVIDENCE_BASE/real-installed-mixed-112-XXXXXX")"
MIXED_SSH_USER="mcpac$RANDOM$RANDOM"
[[ ! -d "/home/$MIXED_SSH_USER" ]] || exit 2
DB_PID=''
CREATED_USER=0
cleanup() {
  local status="$?"
  trap - EXIT
  if [[ "$status" -ne 0 ]]; then
    echo "Disposable setup failed at last reported stage; pre-OAuth log excerpts:" >&2
    for name in composer-install composer-platform wp-config wp-install wp-site-url wp-plugins large-content wp-rewrite gateway-migrations gateway-oauth-keygen gateway-bridge-keygen; do
      if [[ -f "$ROOT/logs/$name.log" ]]; then
        printf '%s: ' "$name" >&2
        if [[ "$name" == gateway-migrations ]]; then
          head -n 22 "$ROOT/logs/$name.log" >&2 || true
        else
          tail -n 3 "$ROOT/logs/$name.log" >&2 || true
        fi
      fi
    done
    if [[ -f "$ROOT/logs/mariadb.log" ]]; then
      tail -n 4 "$ROOT/logs/mariadb.log" >&2 || true
    fi
  fi
  if [[ -S "$ROOT/db.sock" ]]; then
    mysqladmin --no-defaults -uroot --socket="$ROOT/db.sock" shutdown >/dev/null 2>&1 || true
  fi
  if [[ -n "$DB_PID" ]]; then kill "$DB_PID" 2>/dev/null || true; wait "$DB_PID" 2>/dev/null || true; fi
  if [[ "$CREATED_USER" -eq 1 ]]; then userdel -r "$MIXED_SSH_USER" >/dev/null 2>&1 || true; fi
  ssh_state=removed
  if getent passwd "$MIXED_SSH_USER" >/dev/null; then ssh_state=LEAKED; status=1; fi
  if [[ "$ROOT" == /srv/ai-workspace/mcp-gateway-installed-112-* ]]; then
    rm -rf -- "$ROOT"
  fi
  fixture_state=removed
  if [[ -e "$ROOT" ]]; then fixture_state=LEAKED; status=1; fi
  printf 'cleanup_status=%d\nnamespace_components=stopped\nssh_account=%s\ndatabase=removed\nprivate_fixture=%s\n' \
    "$status" "$ssh_state" "$fixture_state" >"$EVIDENCE/cleanup.txt"
  chown -R aiworker:aiworker "$EVIDENCE"
  chmod 600 "$EVIDENCE"/*.txt "$EVIDENCE"/*.json 2>/dev/null || true
  echo "Disposable cleanup completed; sanitized evidence: $EVIDENCE"
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$ROOT"/{wp,gateway,secrets,db,client,logs}
chmod 700 "$ROOT" "$ROOT/secrets"
# Export only version-controlled bytes from the exact commit. Git-ignored
# sessions, .env, compiled views, private keys and untracked test data can
# never enter this staging root, even when git status reports a clean checkout.
git -c safe.directory="$SOURCE" -C "$SOURCE" archive --format=tar HEAD | tar -C "$ROOT/gateway" -xf -
for prohibited in "$ROOT/gateway/.env" "$ROOT/gateway/.git" "$ROOT/gateway/vendor"; do
  if [[ -e "$prohibited" || -L "$prohibited" ]]; then
    echo 'Fresh installed Gateway cannot inherit application credentials, Git internals or vendor.' >&2
    exit 1
  fi
done
for state_dir in "$ROOT/gateway/storage" "$ROOT/gateway/bootstrap/cache"; do
  if find "$state_dir" -type f ! -name '.gitignore' -print -quit | grep -q .; then
    echo 'Tracked application runtime state is not permitted in a fresh installation.' >&2
    exit 1
  fi
done
printf 'source_export=git_archive_exact_head\nignored_checkout_state_imported=no\n' \
  >"$EVIDENCE/source-export.txt"

# Install dependencies independently from the committed Composer lockfile:
# never copy the checkout's ignored vendor directory or generated autoload.
# Keep the private fixture root accessible only to its dedicated worker.
chown aiworker:aiworker "$ROOT"
chown -R aiworker:aiworker "$ROOT/gateway"
runuser -u aiworker -- sh -c 'cd "$1" && composer install --no-dev --no-interaction --prefer-dist --no-progress --optimize-autoloader' \
  sh "$ROOT/gateway" >"$ROOT/logs/composer-install.log" 2>&1
runuser -u aiworker -- sh -c 'cd "$1" && composer check-platform-reqs --no-dev' sh "$ROOT/gateway" \
  >"$ROOT/logs/composer-platform.log" 2>&1
# Composer may create bootstrap manifests; freshly generate them on installed
# first boot, not from prior builds. Every writable runtime path starts empty.
rm -rf -- "$ROOT/gateway/storage" "$ROOT/gateway/bootstrap/cache"
mkdir -p "$ROOT/gateway/bootstrap/cache" \
  "$ROOT/gateway/storage/app/private" "$ROOT/gateway/storage/app/public" \
  "$ROOT/gateway/storage/framework/cache/data" \
  "$ROOT/gateway/storage/framework/mcp-sessions" \
  "$ROOT/gateway/storage/framework/sessions" \
  "$ROOT/gateway/storage/framework/testing" \
  "$ROOT/gateway/storage/framework/views" "$ROOT/gateway/storage/logs"
chown -R aiworker:aiworker "$ROOT/gateway/storage" "$ROOT/gateway/bootstrap/cache"
if find "$ROOT/gateway/storage" "$ROOT/gateway/bootstrap/cache" -type f -print -quit | grep -q .; then
  echo 'Fresh installed Gateway unexpectedly contains runtime state.' >&2
  exit 1
fi
printf 'fresh_storage_files=0\nfresh_bootstrap_cache_files=0\ndependencies=installed_from_tracked_composer_lock\n' \
  >>"$EVIDENCE/source-export.txt"

tar -xzf "$WP_ARCHIVE" -C "$ROOT/wp" --strip-components=1
unzip -q "$WP_BRIDGE_ARCHIVE" -d "$ROOT/wp/wp-content/plugins"
unzip -q "$WP_ADAPTER_ARCHIVE" -d "$ROOT/wp/wp-content/plugins"
cp "$WP_CLI" "$ROOT/wp-cli.phar"
cp "$ROOT/gateway/tests/Support/installed-mixed/client.php" "$ROOT/client/"
cp "$ROOT/gateway/tests/Support/installed-mixed/file-client.php" "$ROOT/client/"
cp "$ROOT/gateway/tests/Support/installed-mixed/file-client.py" "$ROOT/client/"
cp "$ROOT/gateway/tests/Support/installed-mixed/dynamic-ability.php" "$ROOT/client/"
cp "$ROOT/gateway/tests/Support/installed-mixed/FixtureClientProfiles.php" "$ROOT/gateway/app/Providers/"
cat > "$ROOT/gateway/bootstrap/providers.php" <<'EOF_PROVIDERS'
<?php
return [
    \App\Providers\FixtureClientProfiles::class,
    \App\Providers\AppServiceProvider::class,
];
EOF_PROVIDERS
# Trust is scoped to copies in this disposable namespace: normal TLS checks stay ON.
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=disposable-mixed-acceptance' \
    -addext 'subjectAltName=IP:11.22.33.44,IP:11.22.33.45' \
    -keyout "$ROOT/secrets/tls.key" -out "$ROOT/secrets/tls.crt" >"$ROOT/logs/tls-gen.log" 2>&1
cat "$ROOT/secrets/tls.crt" "$ROOT/secrets/tls.key" >"$ROOT/secrets/tls.pem"
cat "$ROOT/secrets/tls.crt" >>"$ROOT/wp/wp-includes/certificates/ca-bundle.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$ROOT/secrets/client-key.pem" >"$ROOT/logs/client-keygen.log" 2>&1
php -r '
$key = openssl_pkey_get_private(file_get_contents($argv[1]));
$rsa = openssl_pkey_get_details($key)["rsa"];
$b64 = static fn($s) => rtrim(strtr(base64_encode($s), "+/", "-_"), "=");
echo json_encode(["keys" => [["kty" => "RSA", "use" => "sig", "alg" => "RS256",
    "kid" => "mixed-acceptance", "n" => $b64($rsa["n"]), "e" => $b64($rsa["e"])]]],
    JSON_THROW_ON_ERROR);
' "$ROOT/secrets/client-key.pem" >"$ROOT/secrets/client-jwks.json"
ssh-keygen -q -t ed25519 -N '' -f "$ROOT/secrets/ssh_host"
awk '{print $1" "$2}' "$ROOT/secrets/ssh_host.pub" >"$ROOT/secrets/ssh_host.pin"
openssl rand -hex 16 >"$ROOT/secrets/ssh-password"
openssl rand -hex 16 >"$ROOT/secrets/wp-password"
chmod 600 "$ROOT/secrets/"*
useradd -m -s /bin/bash "$MIXED_SSH_USER"
CREATED_USER=1
runuser -u "$MIXED_SSH_USER" -- mkdir -m 0700 "/home/$MIXED_SSH_USER/.gateway-transfer-private"
printf '%s:%s\n' "$MIXED_SSH_USER" "$(cat "$ROOT/secrets/ssh-password")" | chpasswd
cat > "$ROOT/secrets/sshd.conf" <<EOF_SSHD
Port 46231
ListenAddress 11.22.33.46
PidFile $ROOT/secrets/sshd.pid
HostKey $ROOT/secrets/ssh_host
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers $MIXED_SSH_USER
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
X11Forwarding no
Subsystem sftp internal-sftp
LogLevel ERROR
EOF_SSHD
printf 'MIXED_SSH_USER=%q\nMIXED_EVIDENCE=%q\n' "$MIXED_SSH_USER" "$EVIDENCE" >"$ROOT/secrets/fixture-env"
cat > "$ROOT/wp/router.php" <<'EOF_ROUTER'
<?php
// The built-in test server has no Apache/Nginx rewrite module. Dispatch
// exactly the Bridge's public paths through its real WordPress parse_request
// hook. All metadata, nonce, consent and OAuth logic stays in the plugin.
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$_SERVER['HTTPS'] = 'on';
$_SERVER['SERVER_PORT'] = 443;
if (is_string($path) && $path !== '/' && is_file(__DIR__.$path)) {
    if (str_ends_with($path, '.php')) { require __DIR__.$path; exit; }
    return false;
}
if (in_array($path, [
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-authorization-server',
    '/wp-ai-bridge/oauth/authorize',
], true)) {
    require __DIR__.'/wp-load.php';
    // Invoke the genuine installed plugin endpoint, never a fixture response.
    $handler = new \WP_AI_Bridge\Auth\OAuth_Server();
    error_log('MIXED_ROUTE_DIAGNOSTIC requested='.json_encode($_SERVER['REQUEST_URI'])
        .' public='.json_encode($handler->protected_resource_metadata_url())
        .' auth='.json_encode($handler->authorization_server_metadata_url()));
    $handler->maybe_handle_public_endpoint();
    http_response_code(404);
    exit;
}
if (is_string($path) && str_starts_with($path, '/wp-json/')) {
    $route = substr($path, strlen('/wp-json'));
    $_GET['rest_route'] = $route;
    $_SERVER['REQUEST_URI'] = '/?rest_route='.rawurlencode($route);
}
require __DIR__.'/index.php';
EOF_ROUTER
cat > "$ROOT/gateway/.env" <<EOF_LARAVEL
APP_NAME="Disposable Mixed MCP Acceptance"
APP_ENV=local
APP_DEBUG=false
APP_URL=https://11.22.33.45
APP_KEY=base64:$(openssl rand -base64 32 | tr -d '\n')
LOG_CHANNEL=single
DB_CONNECTION=mariadb
DB_HOST=localhost
DB_SOCKET=$ROOT/db.sock
DB_DATABASE=gateway
DB_USERNAME=root
DB_PASSWORD=
SESSION_DRIVER=file
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=true
CACHE_STORE=file
QUEUE_CONNECTION=sync
MCP_BOOTSTRAP_FIXTURE_ENABLED=false
SSH_FILE_TRANSFER_ENABLED=true
SSH_FILE_TRANSFER_MAX_BYTES=8388608
SSH_FILE_TRANSFER_MAX_SECONDS=30
MIXED_ACCEPTANCE_JWKS=$ROOT/secrets/client-jwks.json
BRIDGE_REMOTE_CONNECT_TIMEOUT_SECONDS=2
BRIDGE_REMOTE_REQUEST_TIMEOUT_SECONDS=6
BRIDGE_REMOTE_MAX_RESPONSE_BYTES=65536
BRIDGE_REMOTE_READONLY_TOOL_MAX_RESPONSE_BYTES=262144
EOF_LARAVEL
chown -R aiworker:aiworker "$ROOT" "$EVIDENCE"
chmod 700 "$ROOT" "$ROOT/secrets"
chmod 600 "$ROOT/gateway/.env" "$ROOT/secrets/"*
runuser -u aiworker -- mariadb-install-db --no-defaults --datadir="$ROOT/db" \
    --auth-root-authentication-method=normal --skip-test-db >"$ROOT/logs/db-install.log" 2>&1
runuser -u aiworker -- mariadbd --no-defaults --datadir="$ROOT/db" \
    --socket="$ROOT/db.sock" --skip-networking --pid-file="$ROOT/db.pid" \
    --log-error="$ROOT/logs/mariadb.log" --innodb-buffer-pool-size=64M &
DB_PID="$!"
ready_db=0
for try in $(seq 1 75); do
  if mysqladmin --no-defaults -uroot --socket="$ROOT/db.sock" ping >/dev/null 2>&1; then
    ready_db=1; break
  fi
  sleep 0.2
done
[[ "$ready_db" -eq 1 ]] || { echo "Private MariaDB socket startup failed." >&2; exit 1; }
mysql --no-defaults -uroot --socket="$ROOT/db.sock" \
    -e 'CREATE DATABASE wordpress CHARACTER SET utf8mb4; CREATE DATABASE gateway CHARACTER SET utf8mb4;'
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    config create --dbname=wordpress --dbuser=root --dbpass='' --dbhost="localhost:$ROOT/db.sock" \
    --skip-check >"$ROOT/logs/wp-config.log" 2>&1
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    core install --url="https://11.22.33.44" --title="Disposable real WP" \
    --admin_user=mixedadmin --admin_password="$(cat "$ROOT/secrets/wp-password")" \
    --admin_email="mixed@example.invalid" --skip-email >"$ROOT/logs/wp-install.log" 2>&1
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    option update home 'https://11.22.33.44' >"$ROOT/logs/wp-site-url.log" 2>&1
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    option update siteurl 'https://11.22.33.44' >>"$ROOT/logs/wp-site-url.log" 2>&1
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    plugin activate mcp-adapter wp-ai-bridge >"$ROOT/logs/wp-plugins.log" 2>&1
if [[ "$MIXED_BRIDGE_PROFILE" == merged-main-c522ae9 ]]; then
  runuser -u aiworker -- env MIXED_LARGE_POST_FILE="$ROOT/secrets/large-content.json" \
    php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    eval-file "$ROOT/gateway/tests/Support/installed-mixed/large-content.php" \
    >"$ROOT/logs/large-content.log" 2>&1
fi
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    option update permalink_structure '/%postname%/' >"$ROOT/logs/wp-rewrite.log" 2>&1
runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    rewrite flush >>"$ROOT/logs/wp-rewrite.log" 2>&1
# Restrict all groups to their defaults except Native Abilities, needed solely
# for the newly installed read-only provider; mutating groups remain off.
echo "Stage: WordPress Bridge settings"; runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    option update wp_ai_bridge_settings '{"site_read":1,"native_abilities":1}' --format=json >/dev/null
echo "Stage: WordPress OAuth client approval"; runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" \
    option update wp_ai_bridge_oauth_clients '["https://11.22.33.45/oauth/client.json"]' --format=json >/dev/null
echo "Stage: Gateway migration"; cd "$ROOT/gateway"
runuser -u aiworker -- php artisan migrate --force >"$ROOT/logs/gateway-migrations.log" 2>&1
runuser -u aiworker -- php artisan gateway:oauth-keygen --force >"$ROOT/logs/gateway-oauth-keygen.log" 2>&1
runuser -u aiworker -- php artisan gateway:bridge-client-keygen --force >"$ROOT/logs/gateway-bridge-keygen.log" 2>&1
echo "PASS installed fresh WordPress 6.9, WP AI Bridge, MCP Adapter, private MariaDB migrations and Gateway keys."
# Evidence is sanitized. Raw HTTP logs, bearer material and disposable secrets
# are never copied into GitHub, chat responses or persistent evidence.
{
  printf 'source_head=%s\n' "$(git -c safe.directory="$SOURCE" -C "$SOURCE" rev-parse HEAD)"
  printf 'source_tree=%s\n' "$(git -c safe.directory="$SOURCE" -C "$SOURCE" rev-parse HEAD^{tree})"
  printf 'source_version=%s\n' "$(cat "$ROOT/gateway/VERSION")"
  printf 'bridge_fixture_profile=%s\n' "$MIXED_BRIDGE_PROFILE"
  if [[ "$MIXED_BRIDGE_PROFILE" == merged-main-c522ae9 ]]; then
    printf 'bridge_merged_source_sha=%s\n' 'c522ae99bd11926eb74c007d187354013202fc4c'
  fi
  printf 'wordpress_version=%s\n' "$(runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" core version)"
  for plugin in wp-ai-bridge mcp-adapter; do
    printf '%s_version=%s\n' "$plugin" \
      "$(runuser -u aiworker -- php "$ROOT/wp-cli.phar" --path="$ROOT/wp" plugin get "$plugin" --field=version)"
  done
  # Identical SHA-256 preflight on source inputs and retained identity evidence.
  for spec in \
    "wordpress_archive:$WP_ARCHIVE" "wp_cli_phar:$WP_CLI" \
    "wp_bridge_release_zip:$WP_BRIDGE_ARCHIVE" \
    "mcp_adapter_release_zip:$WP_ADAPTER_ARCHIVE"; do
    printf '%s_sha256=%s\n' "${spec%%:*}" "$(sha256sum -- "${spec#*:}" | cut -d' ' -f1)"
  done
  printf 'source_export=git_archive_exact_head\n'
  printf 'runtime_state_imported=no\n'
  printf 'vendor_identity=committed_composer_lock_fresh_install\n'
  printf 'php_version=%s\n' "$(php -r 'echo PHP_VERSION;')"
  printf 'mariadb_version=%s\n' "$(mariadbd --version | head -1)"
  printf 'installed_identity=source-copy-plus-ephemeral-client-provider-only\n'
  printf 'public_release=v2.0.3-not-deployed\n'
} >"$EVIDENCE/identity.txt"
export MIXED_EVIDENCE="$EVIDENCE"
unshare -nm -- "$ROOT/gateway/tests/Support/installed-mixed/run.sh" inside "$ROOT"
echo "PASS all live installed Gateway, WordPress and SSH acceptance stages."
