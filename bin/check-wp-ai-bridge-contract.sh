#!/usr/bin/env bash
set -euo pipefail

gateway_root="$(cd "$(dirname "$0")/.." && pwd)"
bridge_root="${1:?usage: check-wp-ai-bridge-contract.sh <bridge-checkout> <expected-sha>}"
expected_sha="${2:?usage: check-wp-ai-bridge-contract.sh <bridge-checkout> <expected-sha>}"

actual_sha="$(git -C "$bridge_root" rev-parse HEAD)"
if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "ERROR: WP AI Bridge checkout drifted: expected $expected_sha, got $actual_sha" >&2
    exit 1
fi

compose_file="$bridge_root/tests/integration/compose.yml"
if [[ ! -f "$compose_file" ]]; then
    echo "ERROR: pinned WP AI Bridge integration compose file is missing." >&2
    exit 1
fi

export WORDPRESS_TAG="${WORDPRESS_TAG:-6.9-php8.4-apache}"
export COMPOSE_PROJECT_NAME="mcp-gateway-bridge-contract-$$"
compose=(docker compose -f "$compose_file")
cleanup() {
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

bash "$bridge_root/bin/build-zip.sh"
"${compose[@]}" up -d db wordpress

for attempt in $(seq 1 30); do
    if "${compose[@]}" exec -T wordpress test -f /var/www/html/wp-load.php; then
        break
    fi
    if [[ "$attempt" == "30" ]]; then
        echo "ERROR: isolated WordPress files were not initialized." >&2
        exit 1
    fi
    sleep 2
done

"${compose[@]}" cp "$bridge_root/build/wp-ai-bridge.zip" wordpress:/var/www/html/wp-ai-bridge.zip
"${compose[@]}" cp "$gateway_root/tests/Contract/wp_ai_bridge_ambiguous_client_auth.php" wordpress:/var/www/html/wp-ai-bridge-contract.php
wp=("${compose[@]}" run --rm cli)
"${wp[@]}" core install \
    --url=https://localhost \
    --title='MCP Gateway Bridge Contract' \
    --admin_user=admin \
    --admin_password='integration-only-password' \
    --admin_email=admin@example.invalid \
    --skip-email \
    --allow-root
"${wp[@]}" plugin install /var/www/html/wp-ai-bridge.zip --activate --allow-root
"${compose[@]}" exec -T wordpress rm -f /var/www/html/wp-ai-bridge.zip

actual_wp="$("${wp[@]}" core version --allow-root | tail -n 1)"
actual_php="$("${wp[@]}" eval 'echo PHP_VERSION;' --allow-root | tail -n 1)"
echo "Exact Bridge contract baseline: $expected_sha; WordPress $actual_wp; PHP $actual_php"
"${wp[@]}" eval-file /var/www/html/wp-ai-bridge-contract.php --user=1 --allow-root
