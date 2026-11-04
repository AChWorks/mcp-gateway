# Managed Reverse SSH — Issue #270

**Availability and approvals:** Managed Reverse SSH is implemented in the
v2.5.6 source and remains **OFF by default**. Use only an actually published,
independently verified immutable GitHub Release package for installation;
source branches or temporary CI candidate artifacts are not public releases.
Privileged Gateway host bootstrap, installed NL/IR upgrades and real
inbound-blocked Target acceptance require separately authorized host actions.
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
cannot change root-owned SSHD/systemd settings. Privileged bootstrapping
delegates writes inside PHP-writable storage to the PHP service identity
itself (not root) and rejects symlinked storage paths. Existing Direct SSH, manually
approved Reverse SSH, Target ACLs, SFTP, commands and retained Jobs are not
converted to a generic SSH proxy or DNS bypass.

## One-time host bootstrap (separate privileged approval)

Obtain and independently verify an immutable MCP Gateway release package.
The full-install package and the supported Browser Update ZIP both ship **exactly**
`bin/managed-reverse-target.sh` and `bin/managed-reverse-gateway.sh`.
`config/ssh.php` pins SHA256 identities of **both** scripts; the update
manifest and installed-runtime verification cover the same files. Browser
Update creates `bin/` on older installations if missing, but owns only those
two names, not unrelated operator content. Existing unverified files,
symlinks or unsafe directory types block mutation. On an update failure
before migration, verified code restoration removes newly installed scripts
that did not exist previously (or restores old approved bytes), without
removing unrelated `bin/` files. The package ships
`bin/managed-reverse-gateway.sh`, not a mutable script fetched
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

In Admin > System > Reverse SSH, Owner configures the reachable control host,
port, dedicated control user and verified SSHD public host key, with password
confirmation. The PHP configuration is bound to a root-owned manifest at
/etc/mcp-gateway-reverse/manifest.json. Its Owner page distinguishes
`Disabled`, `Needs host setup`, `Ready`, and `Degraded`: a bounded
local TCP/OpenSSH handshake checks the exact independently pinned control
host key, plus the actual PHP-owned authorized-key policy and any pending
publication receipts. `Ready` is only local control-host readiness, NOT proof
of public firewall access, systemd service identity, a working external
Target route, or a completed Target login. Where PHP lacks OS privileges,
the page displays separately approved `systemctl status`, `ss -lntp`
and the immutable host installer `--preflight` commands rather than
silently claiming privileged host inspection. The separate host approval is
required only once, not per added Target. When settings are saved, the Admin page shows a read-only summary and an explicit Edit action. Local Ready status never proves a connected remote Target.

## Adding a Target in one command

Targets > Add Target > SSH > Managed Reverse SSH collects stable ID, real
Target host/SSH port/login and the independently verified Target SSHD public
host key. After Owner password verification it creates a Pending Target,
reserves a unique Gateway loopback port and generates a 10-minute, one-use
enrollment token. The only command is displayed once and contains a sensitive
short-lived token, never a private key. Do not paste it in shared logs/chat.

The one-time installation command appears as the next step of the shared Add Target flow. Failed validation returns to that same flow, restoring only safe non-secret fields. The legacy Managed creation URL redirects to Add Target.

The command downloads the fixed installed Target script over HTTPS to a
temporary file, verifies the exact release-committed SHA256 BEFORE any privileged execution and
executes the script with direct bash when already root or sudo when non-root.
A root-only server does not need sudo installed. Compare the expected digest
against an independently
trusted immutable release manifest: digest and script from the same mutable
web host are not independent provenance.

The installer requires a supported Debian/Ubuntu or RHEL-family Linux with
systemd, curl, Python3, ssh, ssh-keygen, ssh-keyscan and standard utilities.
It validates the local SSHD host key, existing OS login username/home and
unsafe SSH symlink paths against the Owner-entered values BEFORE claim,
creates a separate non-root control user and local private key, sends
the one-use claim over HTTPS, pins Gateway control SSHD, appends only the
returned public Target login key to the existing user and installs the
persistent mcp-gateway-reverse-<ULID>.service (OpenSSH -N -R, strict host pin,
loopback listener, ExitOnForwardFailure and reconnect policy). It refuses
unowned symlinks, services and keys instead of adopting them. Public key
installation inside the Target login user's home and pinned control-key
updates execute under those unprivileged OS identities, not root. It does not
silently alter host firewall or install packages.

Neither claim nor local service start means Connected. The Owner must run
the existing Gateway Target Details > Test action, which verifies real Target
host key and SSH login through the approved listener. A failed first
verification preserves Pending Setup with its exact error code and timestamp;
a previously Connected Target retains ordinary Error health reporting when
its next verification fails. Only a verified test sets Connected. This is
point-in-time proof, not a heartbeat.

## Uncertain results, recovery, revocation and rollback

- A one-use token is consumed exactly once. An ambiguous/missing claim
  response **cannot** be retried automatically; it may already have
  authorized a control key. Neither claim nor file publication is a
  verified Target login or a Connected state.
- The existing Target detail screen offers **Reissue one-use install
  command** for unverified `Pending Setup` enrollments, guarded by
  Owner password and an exact Target-ID confirmation. This preserves the
  Target's original identity, independently pinned real SSH host key,
  login identity and approved private key. The encrypted Target login
  credential is opened under the original trusted binding and re-sealed
  atomically under the new route revision/port/identity, without changing
  the approved secret. This preserves real post-reissue Verify while
  fencing older retained Jobs. The new enrollment rotates
  its **enrollment ULID** (the Target-side state directory, Unix control
  identity and systemd unit namespace), short-lived token, unique loopback
  port, control binding and Job binding revision. An existing Target-side
  state file from an uncertain prior claim cannot be mistaken for the new
  authorized response. Old listener ports remain quarantined because an
  older established `-R` session may still exist; the external Target
  service must be stopped by a separately authorized Target operator.
- A best-effort **Gateway namespace** TCP bind probe excludes already
  occupied loopback ports on enrollment and reissue. This is not a
  promise about cross-namespace listeners or a race-free reservation;
  OpenSSH `ExitOnForwardFailure` remains the authoritative runtime check.
- Key-reader publication and DB intent are deliberately **not** one
  transaction: a one-use claim commits `claimed + publication_pending`
  before a public-key file is atomically published. Only after the
  reader bytes are confirmed and a new DB finalization commits does
  the enrollment become `active`. A failure/crash leaves a durable
  pending receipt and blocks the managed route until Owner
  reconciliation. The Owner can safely retry **Reconcile restricted
  public keys**. Activation is never inferred solely from a written file.
- Owner revocation atomically commits `revoked`, credential deletion,
  a monotonic binding revision for retained Job fencing and the
  Disconnected Target state **before** external key-file publication.
  The host key-removal stage has a separate durable pending receipt;
  failures leave a visible/retriable Owner action. Do not describe
  revocation as fully completed while host policy is still pending.
  Local delete/forget remains blocked until the host reader is reconciled.
- Existing PHP processes coordinate policy publication with claim, reissue,
  revoke and Gateway feature state using a PHP-owned file lock. No PHP
  request gains OS root access. Disabling Gateway routing remains
  possible even if the host reader is damaged; the resulting application
  route then fails closed and host reconciliation is still required.
- The Target installer refuses pre-planted non-root-owned or
  group/world-writable root state directories, malicious lock paths and
  unsafe control-key ownership/mode **before** token consumption. It
  preserves verified partial root-owned state for bounded idempotent
  retries, never recursively follows/reowns a user-controlled tree.
  Existing login account names may contain uppercase letters, dots,
  plus signs and hyphens within the canonical SSH registration contract.
- Removing a public control key prevents **new** control authentication
  but does **not** forcibly terminate already established SSH sessions or
  retroactively stop detached commands. Stop the exact Target
  systemd unit and remove its login public key separately with explicit
  Target authorization.
- Disable the feature in Owner Admin first, then use the verified host
  bootstrap `--disable` with the exact originally approved arguments
  to stop only the owned control SSHD service. This preserves other SSHD
  services, host firewall rules and system accounts.
- Database migration rollback is deliberately fail-closed: all enrollments
  must be revoked without pending publication, Gateway routing disabled
  without pending configuration publication, and the restricted SSHD
  `authorized_keys` reader independently verified empty and reconciled
  with the approved host identity. An unavailable reader is not proof of
  revocation. Superseded Target services and retired listener history also
  require explicit reconciliation; rollback must not silently erase a port
  quarantine while an old reverse forward may survive. A fresh unconfigured
  installation may roll back normally. Reconcile interrupted revocation
  before local Target deletion or schema rollback.

## Acceptance gates

Code lint, static analysis, PHP tests, release-artifact verification and
real isolated OpenSSH/systemd acceptance must pass. The disposable
`managed-reverse-single-command-e2e` job uses the actual generated
single-command installer, real local TLS and one-use HTTP enrollment against
Laravel/SQLite, separately restricted control and Target SSHD identities,
a persistent Target systemd service, real Gateway pinned login/Command/SFTP,
a managed retained SSH Job with verified binding, a second one-command setup after an already claimed but unverified enrollment (new OS account/unit/state while the old files still exist), safe repeat invocation,
explicit stopped-control-host health diagnosis, and systemd reconnection.
It also uses a real existing `deploy.prod` Unix account in CI to cover
the dotted-username contract and rejects unsafe root-state ownership and
lock-file symlinks before claim. A separate disposable Chromium browser
suite tests responsive/dark/RTL Admin recovery views and no-JS denial. It removes
its isolated runtime state afterward. This is a single-host loopback network
simulation; it does not prove cross-border network reachability, a real
whole-machine reboot, all claimed RHEL-family distributions or the
correct firewall on a deployed Gateway. The test asserts `systemctl
is-enabled` plus process/service restart, not a simulated reboot.
Those operator acceptance steps remain separately gated and unverified. Verify false host pins,
wrong listeners, no shell, replay, concurrency, restart/recovery, revocation
and partial outcomes. Green CI is not a production host proof; production
SSHD changes, Merge, release and deployment need exact Owner authorization.
