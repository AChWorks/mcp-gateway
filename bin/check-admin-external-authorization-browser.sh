#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
for tool in php node curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: missing browser test prerequisite: $tool" >&2
        exit 1
    fi
done
if [[ ! -f vendor/autoload.php || ! -f node_modules/playwright/package.json ]]; then
    echo 'ERROR: install Composer and Playwright developer dependencies first.' >&2
    exit 1
fi

umask 077
fixture_dir="$(mktemp -d)"
fixture_pid=''
cleanup() {
    if [[ -n "$fixture_pid" ]]; then
        kill "$fixture_pid" 2>/dev/null || true
        wait "$fixture_pid" 2>/dev/null || true
    fi
    rm -rf -- "$fixture_dir"
}
trap cleanup EXIT
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
touch "$fixture_dir/gateway.sqlite"
export APP_ENV=local APP_DEBUG=false APP_URL="http://127.0.0.1:$port"
export APP_KEY='base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
export DB_CONNECTION=sqlite DB_DATABASE="$fixture_dir/gateway.sqlite"
export SESSION_DRIVER=file SESSION_ENCRYPT=true SESSION_SECURE_COOKIE=false CACHE_STORE=array
export BRIDGE_CLIENT_PRIVATE_KEY_PATH="$fixture_dir/bridge-client/private.key"
export BRIDGE_CLIENT_PUBLIC_KEY_PATH="$fixture_dir/bridge-client/public.key"
export GATEWAY_BROWSER_FIXTURE=1
export GATEWAY_BROWSER_BASE_URL="$APP_URL"

php artisan migrate --force --no-interaction --quiet
php artisan gateway:bridge-client-keygen --force --no-interaction >"$fixture_dir/keygen.log"
php -S "127.0.0.1:$port" -t public tests/Support/external-authorization-browser-router.php     >"$fixture_dir/server.log" 2>&1 &
fixture_pid=$!

ready=false
for attempt in $(seq 1 40); do
    if curl --silent --output /dev/null --max-time 1 "$APP_URL/__browser__/enter"; then
        ready=true
        break
    fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then
        echo 'ERROR: local fixture terminated before readiness.' >&2
        exit 1
    fi
    sleep 0.25
done
if [[ "$ready" != true ]]; then
    echo 'ERROR: local fixture did not become ready.' >&2
    exit 1
fi

node tests/Browser/external-authorization.cjs
