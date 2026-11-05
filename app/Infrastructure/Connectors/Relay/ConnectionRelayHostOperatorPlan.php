<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * Only renders a copyable Owner-operated, explicitly privileged local command.
 * Never executes a shell, mutates host state, or issues attestation.
 */
final readonly class ConnectionRelayHostOperatorPlan
{
    private const INSTALLED_HELPER = '/usr/local/sbin/mcp-gateway-relay';

    /**
     * @return array{preflight:string,retire:string,bootstrap:string,cleanup:string,sha256:string}|null
     */
    public function commands(ConnectionRelay $relay): ?array
    {
        $source = base_path('resources/host/connection-relay-gateway.py');
        if (! preg_match('#\A/[a-zA-Z0-9/_\.-]+\z#D', $source)
            || str_contains($source, '/../') || ! is_file($source) || is_link($source)) {
            return null;
        }
        $expected = config('connection_relays.gateway_retirement_helper_sha256');
        $actual = hash_file('sha256', $source);
        if (! is_string($expected) || preg_match('/\A[a-f0-9]{64}\z/D', $expected) !== 1
            || ! is_string($actual) || ! hash_equals($expected, $actual)) {
            return null;
        }
        $id = (string) $relay->relay_id;
        $recordId = (string) $relay->getKey();
        $fingerprint = $relay->hostFingerprint();
        $revision = (int) $relay->configuration_revision;
        $port = (int) $relay->local_socks_port;
        if (preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\z/D', $id) !== 1
            || preg_match('/\A[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}\z/D', $recordId) !== 1
            || preg_match('/\A[a-f0-9]{64}\z/D', $fingerprint) !== 1
            || $revision < 1 || $revision > 4294967295 || $port < 46000 || $port > 60999) {
            return null;
        }

        $arguments = implode(' ', [
            '--relay-id', escapeshellarg($id),
            '--record-id', escapeshellarg($recordId),
            '--fingerprint', escapeshellarg($fingerprint),
            '--revision', (string) $revision,
            '--local-port', (string) $port,
        ]);
        // Every invocation verifies the installed *root-owned executable*
        // matches the release-pinned helper; an old or replaced binary cannot
        // silently execute under the generated command.
        $verifiedPrefix = "printf '%s\n' ".escapeshellarg($expected.'  '.self::INSTALLED_HELPER)
            .' | sudo sha256sum --check --status && sudo '.self::INSTALLED_HELPER.' ';

        // Copy release source to an isolated root-owned temporary inode, SHA-
        // check the COPIED bytes, and atomically publish without overwriting
        // unknown installed tools. Checking source before sudo is a TOCTOU risk.
        $bootstrapScript = <<<'BASH'
set -euo pipefail
umask 077
source=__SOURCE__
expected=__SHA__
destination=/usr/local/sbin/mcp-gateway-relay
for parent in / /usr /usr/local /usr/local/sbin; do
    test -d "$parent" && test ! -L "$parent" &&
    test "$(stat -c %u "$parent")" = 0 &&
    test -z "$(find "$parent" -maxdepth 0 -perm /022 -print)" ||
        { echo "Untrusted host tool directory" >&2; exit 1; }
done
if test -e "$destination" || test -L "$destination"; then
    test -f "$destination" && test ! -L "$destination" &&
    test "$(stat -c %u "$destination")" = 0 &&
    test -z "$(find "$destination" -maxdepth 0 -perm /022 -print)" &&
    printf '%s\n' "$expected  $destination" | sha256sum --check --status ||
        { echo "Unknown or outdated installed host tool; refusing replacement." >&2; exit 1; }
    exit 0
fi
temp="$(mktemp /usr/local/sbin/.mcp-gateway-relay.XXXXXXXX)"
trap 'rm -f "$temp"' EXIT
install -o root -g root -m 0755 -- "$source" "$temp"
printf '%s\n' "$expected  $temp" | sha256sum --check --status ||
    { echo "Copied helper SHA256 differs from verified release" >&2; exit 1; }
ln -- "$temp" "$destination"
BASH;
        $bootstrapScript = str_replace(
            ['__SOURCE__', '__SHA__'],
            [escapeshellarg($source), escapeshellarg($expected)],
            $bootstrapScript,
        );

        $bootstrap = 'sudo bash -c '.escapeshellarg($bootstrapScript);
        $retire = $verifiedPrefix.'retire '.$arguments;

        return [
            'preflight' => $verifiedPrefix.'preflight '.$arguments,
            'retire' => $retire,
            // One Owner command: verify/install helper once, then retire only
            // the selected local Relay. Unknown binaries are never replaced.
            'cleanup' => $bootstrap.' && '.$retire,
            'bootstrap' => $bootstrap,
            'sha256' => $expected,
        ];
    }
}
