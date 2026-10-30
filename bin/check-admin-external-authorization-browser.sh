#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mode="${1:-browser}"
if [[ "$mode" != browser && "$mode" != concurrency-only && "$mode" != experience-only ]]; then
    echo 'Usage: check-admin-external-authorization-browser.sh [concurrency-only|experience-only]' >&2
    exit 2
fi
for tool in php curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: missing browser test prerequisite: $tool" >&2
        exit 1
    fi
done
if [[ ! -f vendor/autoload.php ]]; then
    echo 'ERROR: install Composer dependencies first.' >&2
    exit 1
fi
if [[ "$mode" != concurrency-only ]]; then
    if ! command -v node >/dev/null 2>&1 || [[ ! -f node_modules/playwright/package.json ]]; then
        echo 'ERROR: full browser mode requires Node and installed Playwright.' >&2
        exit 1
    fi
fi

umask 077
fixture_dir="$(mktemp -d)"
fixture_pids=()
cleanup() {
    result=$?
    if [[ "$result" -ne 0 ]]; then
        echo '--- disposable HTTP fixture server log (last 40 lines) ---' >&2
        for log_file in "$fixture_dir/server.log" "$fixture_dir/worker-one.log" "$fixture_dir/worker-two.log"; do
            tail -n 24 "$log_file" >&2 2>/dev/null || true
        done
        if [[ -f "$fixture_dir/storage/logs/laravel.log" ]]; then
            echo '--- disposable Laravel error log (last 35 lines) ---' >&2
            tail -n 35 "$fixture_dir/storage/logs/laravel.log" >&2 2>/dev/null || true
        fi
    fi
    for pid in "${fixture_pids[@]}"; do
        pkill -TERM -P "$pid" 2>/dev/null || true
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${fixture_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    rm -rf -- "$fixture_dir"
}
trap cleanup EXIT
read -r port port_one port_two < <(python3 -c 'import socket; s=[socket.socket() for _ in range(3)]; [x.bind(("127.0.0.1",0)) for x in s]; print(*(x.getsockname()[1] for x in s)); [x.close() for x in s]')
touch "$fixture_dir/gateway.sqlite"
mkdir -p "$fixture_dir/storage/framework/sessions" "$fixture_dir/storage/framework/cache/data" \
    "$fixture_dir/storage/framework/views" "$fixture_dir/storage/logs" "$fixture_dir/races"
export LARAVEL_STORAGE_PATH="$fixture_dir/storage"
export GATEWAY_BROWSER_FIXTURE_RACE_DIR="$fixture_dir/races"
export GATEWAY_BROWSER_RACE_GET_ONE_URL="http://127.0.0.1:$port_one"
export GATEWAY_BROWSER_RACE_GET_TWO_URL="http://127.0.0.1:$port_two"
export APP_ENV=local APP_DEBUG=false APP_URL="http://127.0.0.1:$port"
export APP_KEY='base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
export DB_CONNECTION=sqlite DB_DATABASE="$fixture_dir/gateway.sqlite"
export SESSION_DRIVER=file SESSION_ENCRYPT=true SESSION_SECURE_COOKIE=false CACHE_STORE=file
export BRIDGE_CLIENT_PRIVATE_KEY_PATH="$fixture_dir/bridge-client/private.key"
export BRIDGE_CLIENT_PUBLIC_KEY_PATH="$fixture_dir/bridge-client/public.key"
export GATEWAY_BROWSER_FIXTURE=1
export GATEWAY_ADMIN_EXPERIENCE_FIXTURE=1
export GATEWAY_BROWSER_BASE_URL="$APP_URL"

php artisan migrate --force --no-interaction --quiet
php artisan gateway:bridge-client-keygen --force --no-interaction >"$fixture_dir/keygen.log"
PHP_CLI_SERVER_WORKERS=4 php -S "127.0.0.1:$port" -t public tests/Support/external-authorization-browser-router.php \
    >"$fixture_dir/server.log" 2>&1 &
fixture_pids+=("$!")
# Separate listener processes force distinct PHP workers into the race.
# All three share the same disposable encrypted file session and file cache.
PHP_CLI_SERVER_WORKERS=1 php -S "127.0.0.1:$port_one" -t public tests/Support/external-authorization-browser-router.php \
    >"$fixture_dir/worker-one.log" 2>&1 &
fixture_pids+=("$!")
PHP_CLI_SERVER_WORKERS=1 php -S "127.0.0.1:$port_two" -t public tests/Support/external-authorization-browser-router.php \
    >"$fixture_dir/worker-two.log" 2>&1 &
fixture_pids+=("$!")

for url in "$APP_URL" "$GATEWAY_BROWSER_RACE_GET_ONE_URL" "$GATEWAY_BROWSER_RACE_GET_TWO_URL"; do
    ready=false
    for attempt in $(seq 1 40); do
        if curl --fail --silent --output /dev/null --max-time 1 "$url/up"; then
            ready=true
            break
        fi
        sleep 0.25
    done
    if [[ "$ready" != true ]]; then
        echo 'ERROR: a local HTTP worker did not become ready.' >&2
        exit 1
    fi
done

if [[ "$mode" != experience-only ]]; then
    python3 tests/Support/external_authorization_concurrency.py
fi
if [[ "$mode" == browser ]]; then
    node tests/Browser/external-authorization.cjs
fi
if [[ "$mode" != concurrency-only ]]; then
    node tests/Browser/admin-experience.cjs
fi
