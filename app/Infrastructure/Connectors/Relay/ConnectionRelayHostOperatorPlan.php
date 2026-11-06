<?php

namespace App\Infrastructure\Connectors\Relay;

/**
 * Only renders copyable Owner-operated, explicitly privileged local commands.
 * PHP never executes a shell, updates a host tool, or issues attestation.
 */
final readonly class ConnectionRelayHostOperatorPlan
{
    private const INSTALLED_HELPER = '/usr/local/sbin/mcp-gateway-relay';

    /**
     * @return array{preflight:string,audit_gateway:string,retire:string,prepare_setup:string,bootstrap:string,upgrade:string,upgrade_from_sha256:string,cleanup:string,cleanup_for_rotation:string,seal_delete:string,seal_rotate:string,sha256:string}|null
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
        $previous = config('connection_relays.gateway_retirement_helper_upgrade_from_sha256');
        if (! is_string($previous) || preg_match('/\A[a-f0-9]{64}\z/D', $previous) !== 1
            || hash_equals($expected, $previous)) {
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
        // A single privileged shell holds a SHARED installer lock from
        // executable validation through the helper's exit. The installer
        // takes the EXCLUSIVE side before renaming the installed inode.
        // Splitting hash verification and execution into separate sudo calls
        // would permit an Upgrade to swap the binary in between.
        $verifiedScript = <<<'BASH'
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
umask 077
expected=__SHA__
destination=__DESTINATION__
lock=/run/mcp-gateway-relay-helper-install.lock
for parent in / /usr /usr/local /usr/local/sbin /run; do
    test -d "$parent" && test ! -L "$parent" &&
    test "$(stat -c %u "$parent")" = 0 &&
    test -z "$(find "$parent" -maxdepth 0 -perm /022 -print)" ||
        { echo "Untrusted host helper directory" >&2; exit 1; }
done
if test -e "$lock" || test -L "$lock"; then
    test -f "$lock" && test ! -L "$lock" &&
    test "$(stat -c %u "$lock")" = 0 &&
    test -z "$(find "$lock" -maxdepth 0 -perm /022 -print)" ||
        { echo "Untrusted helper lock" >&2; exit 1; }
fi
exec 9>"$lock"
test -f "$lock" && test ! -L "$lock" &&
test "$(stat -c %u "$lock")" = 0 &&
test -z "$(find "$lock" -maxdepth 0 -perm /022 -print)" ||
    { echo "Untrusted helper lock after open" >&2; exit 1; }
flock -s -w 15 9 ||
    { echo "Helper upgrade lock busy; retry after operator maintenance" >&2; exit 1; }
test -f "$destination" && test ! -L "$destination" &&
test "$(stat -c %u "$destination")" = 0 &&
test "$(stat -c %a "$destination")" = 755 &&
test -x "$destination" ||
    { echo "Unsafe or non-executable installed Gateway Relay helper" >&2; exit 1; }
printf '%s\n' "$expected  $destination" | /usr/bin/sha256sum --check --status ||
    { echo "Installed Gateway Relay helper differs from the pinned release" >&2; exit 1; }
# The root shell keeps fd 9 open until this exact verified invocation exits.
"$destination" __ACTION__
BASH;
        $verifiedCommand = static function (string $action) use ($verifiedScript, $expected): string {
            $body = str_replace(
                ['__SHA__', '__DESTINATION__', '__ACTION__'],
                [escapeshellarg($expected), escapeshellarg(self::INSTALLED_HELPER), $action],
                $verifiedScript,
            );

            return '/usr/bin/sudo /usr/bin/bash -c '.escapeshellarg($body);
        };

        // Copy release source to an isolated root-owned temporary inode, SHA-
        // check the COPIED bytes, and atomically publish without overwriting
        // unknown installed tools. Checking source before sudo is a TOCTOU risk.
        $bootstrapScript = <<<'BASH'
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
umask 077
source=__SOURCE__
expected=__SHA__
previous=__PREVIOUS__
mode=__MODE__
destination=__DESTINATION__
for parent in / /usr /usr/local /usr/local/sbin; do
    test -d "$parent" && test ! -L "$parent" &&
    test "$(stat -c %u "$parent")" = 0 &&
    test -z "$(find "$parent" -maxdepth 0 -perm /022 -print)" ||
        { echo "Untrusted host tool directory" >&2; exit 1; }
done
# Serialize installer invocations. The per-Relay lifecycle lock remains the
# authority for active host operations; this install lock never replaces it.
lock=/run/mcp-gateway-relay-helper-install.lock
test -d /run && test ! -L /run &&
test "$(stat -c %u /run)" = 0 &&
test -z "$(find /run -maxdepth 0 -perm /022 -print)" ||
    { echo "Untrusted installer lock directory" >&2; exit 1; }
if test -e "$lock" || test -L "$lock"; then
    test -f "$lock" && test ! -L "$lock" &&
    test "$(stat -c %u "$lock")" = 0 &&
    test -z "$(find "$lock" -maxdepth 0 -perm /022 -print)" ||
        { echo "Untrusted installer lock" >&2; exit 1; }
fi
exec 9>"$lock"
test -f "$lock" && test ! -L "$lock" &&
test "$(stat -c %u "$lock")" = 0 &&
test -z "$(find "$lock" -maxdepth 0 -perm /022 -print)" ||
    { echo "Untrusted installer lock after open" >&2; exit 1; }
flock -x -w 15 9 || { echo "Another Relay helper installer is active" >&2; exit 1; }
installed_previous=no
if test -e "$destination" || test -L "$destination"; then
    test -f "$destination" && test ! -L "$destination" &&
    test "$(stat -c %u "$destination")" = 0 &&
    test -z "$(find "$destination" -maxdepth 0 -perm /022 -print)" ||
        { echo "Unknown or unsafe installed host tool; refusing replacement." >&2; exit 1; }
    if printf '%s\n' "$expected  $destination" | sha256sum --check --status; then
        test "$(stat -c %a "$destination")" = 755 && test -x "$destination" ||
            { echo "Installed helper has invalid executable permissions; refusing success." >&2; exit 1; }
        exit 0
    fi
    if test "$mode" != upgrade ||
        ! printf '%s\n' "$previous  $destination" | sha256sum --check --status; then
        echo "Unknown or outdated installed host tool; refusing replacement." >&2
        exit 1
    fi
    test "$(stat -c %a "$destination")" = 755 && test -x "$destination" ||
        { echo "Previous helper has invalid executable permissions; refusing upgrade." >&2; exit 1; }
    installed_previous=yes
fi
if test "$mode" = upgrade && test "$installed_previous" != yes; then
    echo "No known predecessor to upgrade; use the separate first-install command." >&2
    exit 1
fi
temp="$(mktemp /usr/local/sbin/.mcp-gateway-relay.XXXXXXXX)"
trap 'rm -f "$temp"' EXIT
install -o root -g root -m 0755 -- "$source" "$temp"
printf '%s\n' "$expected  $temp" | sha256sum --check --status ||
    { echo "Copied helper SHA256 differs from verified release" >&2; exit 1; }
sync -f "$temp"
if test "$installed_previous" = yes; then
    # Only an explicitly requested, exact known predecessor may be replaced.
    # A same-directory rename switches the executable atomically. Already
    # running helper processes retain their old inode and per-Relay locks.
    test -f "$destination" && test ! -L "$destination" &&
    test "$(stat -c %u "$destination")" = 0 &&
    test -z "$(find "$destination" -maxdepth 0 -perm /022 -print)" &&
    printf '%s\n' "$previous  $destination" | sha256sum --check --status ||
        { echo "Installed helper changed during verified upgrade" >&2; exit 1; }
    mv -T -- "$temp" "$destination"
else
    # First install must never overwrite another executable.
    ln -- "$temp" "$destination"
fi
sync -f "$destination"
test "$(stat -c %a "$destination")" = 755 && test -x "$destination" ||
    { echo "Published helper has invalid executable permissions" >&2; exit 1; }
printf '%s\n' "$expected  $destination" | sha256sum --check --status ||
    { echo "Published helper SHA256 mismatch" >&2; exit 1; }
BASH;
        $bootstrapScript = str_replace(
            ['__SOURCE__', '__SHA__', '__PREVIOUS__', '__MODE__', '__DESTINATION__'],
            [escapeshellarg($source), escapeshellarg($expected), escapeshellarg($previous), 'install', escapeshellarg(self::INSTALLED_HELPER)],
            $bootstrapScript,
        );
        // Upgrade is a distinct, visible Owner action. Ordinary cleanup and
        // first-time bootstrap must never silently replace an installed tool.
        $upgradeScript = str_replace('mode=install', 'mode=upgrade', $bootstrapScript);
        $bootstrap = '/usr/bin/sudo /usr/bin/bash -c '.escapeshellarg($bootstrapScript);
        $upgrade = '/usr/bin/sudo /usr/bin/bash -c '.escapeshellarg($upgradeScript);
        // Disable advances the DB security revision to N+1 without altering
        // the still-installed N host. Retire must authenticate either exact
        // owned identity and then emit a receipt for CURRENT N+1. The Seal
        // command never accepts the prior fingerprint or a prior revision.
        $prior = $revision > 1
            ? ' --prior-fingerprint '.escapeshellarg($relay->hostFingerprint($revision - 1))
            : '';
        $retire = $verifiedCommand('retire '.$arguments.$prior);
        $sealDelete = $verifiedCommand('seal-delete '.$arguments);
        $sealRotate = $verifiedCommand('seal-rotate '.$arguments);
        // Only an exact, privileged Seal result can skip Retirement. An old
        // rotation fence may still exist while the NEW revision owns live
        // resources, so a shell `test -e` is not a lifecycle decision.
        $cleanupDelete = self::cleanupSequence($sealDelete, $retire);
        $cleanupRotate = self::cleanupSequence($sealRotate, $retire);

        return [
            'preflight' => $verifiedCommand('preflight '.$arguments.$prior),
            // A root-run local-policy audit never writes a readiness lease.
            // The UID comes from this web process, not from an Owner-supplied
            // form or mutable Relay metadata. CLI/queue identity must still
            // be independently confirmed by the host operator.
            'audit_gateway' => $verifiedCommand('audit-gateway '.$arguments
                .' --php-uid '.(function_exists('posix_geteuid') ? (string) max(0, posix_geteuid()) : '0')),
            'prepare_setup' => $verifiedCommand('prepare-setup '.$arguments),
            'retire' => $retire,
            // The final seal shares the privileged lock with prepare-setup.
            // Cleanup receipts without an irreversible fence MUST NOT allow
            // DB deletion or sensitive identity rotation.
            'cleanup' => $bootstrap.' && '.$cleanupDelete,
            'cleanup_for_rotation' => $bootstrap.' && '.$cleanupRotate,
            'seal_delete' => $sealDelete,
            'seal_rotate' => $sealRotate,
            'bootstrap' => $bootstrap,
            'upgrade' => $upgrade,
            'upgrade_from_sha256' => $previous,
            'sha256' => $expected,
        ];
    }

    /**
     * Try the exact current Seal first for safe proof renewal. When it fails,
     * inspect/retire exact claimed host resources and then Seal. The first
     * failed probe's stderr is intentionally hidden because the actionable
     * error comes from the subsequent privileged retirement/Seal attempt.
     */
    private static function cleanupSequence(string $seal, string $retire): string
    {
        return 'if sealed=$('.$seal.' 2>&1); then printf "%s\n" "$sealed"; else '.$retire.' && '.$seal.'; fi';
    }
}
