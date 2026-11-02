# Managed Reverse SSH — Issue #270

**Status:** development candidate only. Independent review, release, isolated
host acceptance and production host changes require separate Owner approval.
The existing manual operator runbook remains supported.

## Architecture

Managed mode is optional and OFF by default. A Target behind an inbound
firewall dials a dedicated, restricted OpenSSH control SSHD on Gateway, then
offers a single per-Target loopback remote forward. Gateway authenticates to
the actual Target with the original pinned SSHD host key and a login private
key held only in its encrypted Target vault. The Target keeps a different,
dedicated control private key on the Target filesystem.

The hosted control SSHD uses a non-root, no-shell user, public-key-only
authentication, remote-forward-only permission, an exact loopback
permitlisten per key, an isolated systemd unit and an independent host key.
The PHP-FPM application writes only an owned restricted public-key file; it
cannot change root-owned SSHD/systemd settings. Existing Direct SSH, manually
approved Reverse SSH, Target ACLs, SFTP, commands and retained Jobs are not
converted to a generic SSH proxy or DNS bypass.

## One-time host bootstrap (separate privileged approval)

Obtain and independently verify an immutable MCP Gateway release package.
The package ships bin/managed-reverse-gateway.sh, not a mutable script fetched
from main. With separately approved NL host changes, preflight first:

    sudo bash /path/to/verified-release/bin/managed-reverse-gateway.sh --preflight --app /real/gateway/path --php-user www --port 7770

Then, only with authorization to create the isolated host account, SSHD
service, key-reader and root-owned host manifest:

    sudo bash /path/to/verified-release/bin/managed-reverse-gateway.sh --apply --app /real/gateway/path --php-user www --port 7770

This does not change the existing SSHD config, existing SSH service or
firewall. Inspect actual systemd status, listener and OpenSSH effective
restrictions independently. The resulting public control SSHD host key must
be verified by a trusted channel. An HTTPS-only CDN proxy is NOT a TCP/SSH
forwarder; the control port needs separate egress reachability from Target.

In Admin > Reverse SSH settings, Owner configures the reachable control host,
port, dedicated control user and verified SSHD public host key, with password
confirmation. The PHP configuration is bound to a root-owned manifest at
/etc/mcp-gateway-reverse/manifest.json. The status intentionally does not
claim successful host-level verification merely because a key file exists.
The separate host approval is required only once, not per added Target.

## Adding a Target in one command

Admin > Targets > Add Target > Managed Reverse SSH collects stable ID, real
Target host/SSH port/login and the independently verified Target SSHD public
host key. After Owner password verification it creates a Pending Target,
reserves a unique Gateway loopback port and generates a 10-minute, one-use
enrollment token. The only command is displayed once and contains a sensitive
short-lived token, never a private key. Do not paste it in shared logs/chat.

The command downloads the fixed installed Target script over HTTPS to a
temporary file, verifies the exact release-committed SHA256 BEFORE any privileged execution and
executes the script with direct bash when already root or sudo when non-root.
A root-only server does not need sudo installed. Compare the expected digest
against an independently
trusted immutable release manifest: digest and script from the same mutable
web host are not independent provenance.

The installer requires a supported Debian/Ubuntu or RHEL-family Linux with
systemd, curl, Python3, ssh, ssh-keygen, ssh-keyscan and standard utilities.
It validates the local SSHD host key against the Owner-entered pin BEFORE
claim, creates a separate non-root control user and local private key, sends
the one-use claim over HTTPS, pins Gateway control SSHD, appends only the
returned public Target login key to the existing user and installs the
persistent mcp-gateway-reverse-<ULID>.service (OpenSSH -N -R, strict host pin,
loopback listener, ExitOnForwardFailure and reconnect policy). It refuses
unowned symlinks, services and keys instead of adopting them. It does not
silently alter host firewall or install packages.

Neither claim nor local service start means Connected. The Owner must run
the existing Gateway Target Details > Test action, which verifies real Target
host key and SSH login through the approved listener. Only that verified
test can set Connected. This is point-in-time proof, not a heartbeat.

## Uncertain results, recovery, revocation and rollback

- Hashed one-use token, expiry, DB uniqueness, per-Target route approval and
  no silent Direct fallback prevent cross-Target replay. Repeated claims fail
  without reauthorization.
- If claim response is lost, treat it as uncertain, not safe to retry.
  Successful Target response is saved in root-only local state for safe
  local setup continuation. Otherwise revoke/reconcile with Owner and create
  a fresh enrollment; do not reuse a consumed token.
- Owner can disable managed routing or reconcile an authorized-keys policy
  without host privileges. Host account/service repair still requires a
  separately authorized root bootstrap.
- Managed Target SSH endpoint/route/credential updates are rejected until the
Owner first revokes the live managed enrollment, preventing an authorized
control-key listener from being orphaned by a silent Direct route edit.
Owner-only Target revocation requires exact ID and password. It removes
  control key admission, local login credential and bumps the binding
  revision to fence retained Jobs. Normal disconnect/forget cannot silently
  leave a managed control public key authorized.
- Removing an authorized key does NOT forcibly terminate already established
  SSH sessions. Stop the exact Target systemd unit and remove its owned login
  key in a separately approved Target-side cleanup.
- Disable the feature in Admin first to fail-close application access, then
  with separate host authorization run verified host bootstrap --disable
  with the same full arguments to stop only the owned control SSHD service.
  This preserves durable state and does not touch original SSHD/firewall.
- Migration rollback is intentionally blocked while non-revoked managed
  enrollments exist. Revoke and reconcile before rollback.

## Acceptance gates

Code lint, static analysis, PHP tests, release-artifact verification and
real isolated OpenSSH/systemd acceptance must pass. The disposable
`managed-reverse-single-command-e2e` job uses the actual generated
single-command installer, real local TLS and one-use HTTP enrollment against
Laravel/SQLite, separately restricted control and Target SSHD identities,
a persistent Target systemd service, real Gateway pinned login/Command/SFTP,
safe repeat invocation, disconnection and systemd reconnection. It removes
its isolated runtime state afterward. This is a single-host loopback network
simulation; it does not prove cross-border network reachability or actual
host reboot persistence. Verify false host pins,
wrong listeners, no shell, replay, concurrency, restart/recovery, revocation
and partial outcomes. Green CI is not a production host proof; production
SSHD changes, Merge, release and deployment need exact Owner authorization.
