# Connection Relays — owner/operator runbook (Issue #284)

**Core Relay routing, inactive Gateway Setup/Retry, root-verified V2 public-key export and inert peer-side staging are merged through PR #294, but have not been published, installed or accepted on real hosts.** The exported public key is bound to the exact configuration revision, fingerprint and Gateway host generation. This runbook's generic peer-host naming is a source change pending independent review. Independent operational readiness attestation and restricted live intermediary enrollment remain unfinished. Production host setup, firewall edits, SSH identity creation, installation, migrations, integration and release require separate approvals and verification. A saved Relay alone does not mean a tunnel is running or that the actual Target is authenticated.

## Intent and architecture

Connection Relay is a reusable per-Target transport route, not a third connector, a per-Target tunnel, a generic HTTP proxy or a VPN. Direct remains the default. Existing Managed and Manual Reverse SSH remain intact and cannot be combined with the new Relay for the same SSH Target.

    Gateway dedicated PHP-FPM UID -> 127.0.0.1:<relay-SOCKS-port>
    -> restricted Gateway OpenSSH client -D -> intermediary restricted SSH control user
    -> validated numeric public Target IP:port
    -> end-to-end SSH host-key pin or HTTPS TLS SNI and certificate check

Each Relay requires one control-plane SSH identity/key completely distinct from the Target login credential and the existing Reverse SSH control identities. The Gateway performs bounded public DNS and numeric destination approval locally, sends only numeric SOCKS5 CONNECT, preserves the real SSH Target host key or HTTPS certificate, and never treats the SOCKS reply as verified remote peer identity. No automatic fallback to Direct. Only deliberate Target operations use a relay; ChatGPT signed-file ingress and unrelated Gateway services remain Direct.

## Unified Create / Edit / Delete lifecycle (required product acceptance; not yet delivered)

Gateway is the **unprivileged control plane**, not a root-level package manager. Its user journey must offer one cohesive lifecycle for multiple independently managed Relay resources:

| Owner action | What Gateway may do | Privileged host action and proof |
| --- | --- | --- |
| Create | Save an inactive draft and prepare a scoped, easy-to-copy Setup instruction | Prepare dedicated UID/ACL, SSH identity, keys and supervised listener; constrain intermediary principal/egress; independently verify both sides; issue root-owned short-lived readiness evidence |
| Rename | Change only the display name with Owner reauthentication and optimistic revision check | **No host command**, no connection interruption or Target epoch reset |
| Edit host, port, key, username, identity or local listener | Disable/detach Targets, require verified root-owned `rotate` fence for the old revision before DB commit | **Gateway-only cleanup + `seal-rotate` under the same root lock as Setup**; old revision cannot be provisioned after fencing; only a newer revision can proceed to future Setup/attestation |
| Disable or diagnose | Fail closed for explicitly bound Targets and show distinct host/control/Target status | Host service changes require a reviewed privileged action; no implicit Direct fallback |
| Delete | Require explicit Target detach/reassignment, disable, Owner confirmation, fresh exact-registration cleanup receipt **and irreversible `delete` fence** | **Scoped cleanup + `seal-delete` on the Gateway host** permanently forbids any future Setup/Repair for that exact DB ULID, including after DB deletion. No intermediary connectivity, remote cleanup, or sibling/Reverse SSH resource change |

The command must be generated for the exact Relay and checked revision; support an independently transferred/offline intermediary-side package when intermediary cannot fetch code from foreign endpoints. No arbitrary shell construction from form inputs, production root execution by PHP, generic destructive purge or silently claimed success. Failure leaves a recoverable disabled registration with an actionable Retry/Repair. Host resource changes must be idempotent, ownership-scoped and positively verified. A successful response from a script alone is not evidence that the Target was authenticated.

**Interim security boundary:** The application now separates display-only rename from sensitive route changes and forbids hard deletion based on an Owner checkbox or absent attestation file. Final deletion requires Owner acknowledgement, a **privileged, short-lived root-owned Gateway-host cleanup receipt** AND an **irreversible, root-owned `delete` fence** bound to exact DB ULID, Relay ID, fingerprint, revision and host generation. An ordinary receipt alone never authorizes DB deletion or sensitive identity rotation. It does **not** require intermediary reachability, remote cleanup evidence or intermediary SSH credentials. The exact-receipt verifier and scoped Gateway-host-only retirement helper were merged in PR #286, but are not installed or operationally accepted. The helper must be installed by the separately authorized host operator; it is NOT a tunnel installer or host-readiness attester. **Do not present Create/Edit/Setup as finished or claim this is deployed.** The UI preserves records instead of fabricating cleanup. This receipt is never to be hand-authored by PHP or fabricated by an operator.

The receipt is located at `/etc/mcp-gateway/connection-relays/<relay-id>.retired.json` (fixed root-owned, symlink-free namespace) and contains exactly `relay_record_id`, `relay_id`, `host_fingerprint`, `configuration_revision`, `host_generation`, `verified_boot_id`, `verified_at_unix`, `verified_at_boot_seconds`, `expires_at_unix`, `gateway_cleanup_verified`. The single boolean must be true **based on independent privileged verification on the Gateway host**. The lease is valid for no more than 900 seconds, with no significant wall-clock/boot-clock divergence. Active policy and readiness files must be gone. There is no intermediary cleanup field or network check: an unreachable intermediary server must never prevent Gateway-side deletion after local verification and Owner confirmation. Remote cleanup, if desired, is an optional separate follow-up. Real-host operational acceptance and a distinct setup/update helper are still required before whole-product acceptance.

### Durable cross-process lifecycle fence (R1 race closure)

A PHP DB transaction cannot hold the privileged helper's root-only `/run`
`flock`, and a second read of `.generation.json` cannot close this race.
Instead, an approved host operator first runs `seal-delete` or `seal-rotate`
**after** successful `retire`, while holding the SAME root-only per-Relay
exclusive lock as `prepare-setup`. The operator's single copyable command
includes cleanup and the required seal. No PHP endpoint invokes `sudo`.

The helper writes a non-secret root-owned, mode 0644 and fsync'd durable
fence at `/etc/mcp-gateway/connection-relays/.fences/<record-ULID>.json`
under trusted root-owned, PHP-traversable parents. The exact keys are
`version=1`, `relay_record_id`, `relay_id`, `host_fingerprint`,
`configuration_revision`, `host_generation` and `intent=delete|rotate`.
The fence matches the current **retired** generation and independently
issued cleanup receipt; PHP checks its owner, strict schema, exact identity,
revision and intended action before running the existing receipt verifier.
`seal-delete` permits only deletion; `seal-rotate` permits only an identity
change that advances `configuration_revision`. This is not a reusable
"approval checkbox" or a claim of active Target readiness.

**Concurrency rule:** An in-flight `prepare-setup` with the root lock wins
before a seal only by invalidating the old retirement generation, causing
the seal to fail. If the seal wins first, all later `prepare-setup` and
`retire` commands for the fenced revision fail before modifying host state.
For `delete`, every revision of that **exact record ULID** is barred
permanently. For `rotate` at revision N, revisions <=N remain forbidden,
while a strictly newer revision can subsequently begin separately approved
Setup. The fence survives cleanup, DB COMMIT, receipt expiry, and host
reboot and MUST NOT be removed by an operator just to unblock old commands.
Future Setup/Repair implementations must use this same guarded helper protocol
and root lock; bypassing either invalidates the safety contract.

If the PHP transaction fails **after** sealing, the registration remains
recoverable: retry the same Owner action. An exact repeat `seal-delete` or
`seal-rotate` re-verifies the empty Gateway-host namespace and can renew the
short-lived receipt without removing the fence or changing host generation.
After `seal-delete`, sensitive edits of that same registration are intentionally
refused; the operator cannot reinterpret it as a rotation. New registration
ULIDs have distinct fences, but reuse of the same Relay ID while an old host
generation exists requires separately reviewed reconciliation, not silent
adoption or removal of the old permanent fence.

**This is a protocol between cooperating privileged helpers**, not protection
against an authorized Root actor that deliberately writes host resources
outside the helper. No release or real-host test has occurred.

## Owner-run staged Gateway Setup and interrupted-Setup recovery (merged source; not installed)

The exact, root-only `setup-gateway` command now generated by the Owner's
Connection Relays page is a **Gateway resource stager**, not a readiness
issuer or intermediary enrollment script. The command is bound to the immutable DB
record ULID, Relay namespace, current revision/fingerprint, local SOCKS port,
separately verified pinned server host key, requested control endpoint, and
the web process's effective PHP UID. The helper **recomputes the full PHP
registration fingerprint** from those inputs before changing host state;
unknown/modified helper source bytes are refused by the existing
release-SHA256-verified Owner command and shared installer lock.

Under the **same exclusive per-Relay root lifecycle lock** as Cleanup/Seal,
the stager checks the permanent Delete/Rotate fences and creates a new
random root-owned generation **before** touching service, credentials or
firewall. An exact root-owned `<relay-id>.setup.json` journal records the
active generation, exact planned systemd unit digest, and all nonsecret inputs
before user creation. Immediately after creating the non-login Unix identity,
the helper durably binds its numeric UID to the journal; the passwd GECOS
field carries the exact per-record/per-generation ownership marker so an
interruption between useradd and journal update remains recoverable. On retry,
a journal with different registration, revision, PHP UID, endpoint, host key
digest or original SSH UID causes refusal. A pre-existing or replacement SSH
principal without matching root-journal identity is never adopted. An
interrupted attempt can resume from the same generation without regenerating
the control key or appending duplicate nftables rules.
Owner may retry the SAME `setup-gateway` command; `prepare-setup` remains a
separate legacy generation-barrier action and must not be reissued over an
active Setup journal.

The stager creates only this Relay's independently named dedicated non-root
Unix SSH identity, root-controlled 0700 credential directory and Ed25519 key,
exact pinned `known_hosts`, root-owned `owner.json`, fixed systemd service,
and a dedicated `inet` output table scoped to its reserved SOCKS5 port.
OpenSSH uses a single `-D 127.0.0.1:<port>`, no session/proxy/jump,
`NoNewPrivileges`, `PrivateTmp` and systemd `LoadCredential=` for the
root-owned key and host pin. The staged unit's `ExecStartPre` invokes the
same root-only installed helper's `ensure-acl` for reboot/restart recovery:
it securely recreates the **same root-owned per-Relay lock directory/file**
when `/run` has been emptied by a reboot, never a separate lock or an
unlocked fast path. Concurrent first-boot creation accepts only a previously
created root-owned, non-writable directory. It verifies the claimed table
without mutation when present; in **both** existing-table and missing-table
paths it holds the same exclusive Relay lifecycle lock as Setup/Retire/Seal.
When the table is absent, it proves exact current journal/manifest/unit and
policy-source identity before restoring only that table. Any drifted foreign
rule, missing claim, changed unit or revoked generation fails closed; no
`flush ruleset` or sibling Relay table is allowed.

The setup script intentionally leaves the new service **INACTIVE and
DISABLED**, without executing a remote connection. The present Gateway may
still share a PHP UID with sibling websites; staging a reachable SOCKS
listener before independently verifying a dedicated FPM/CLI identity and
intermediary forwarding restrictions would violate the security boundary. Source
support for operator-controlled activation and an independent trusted
readiness issuer remains a separate acceptance requirement. `setup-gateway`
is an idempotent scoped retry of the same configured state, **not** an override
of foreign/malformed host state. On a first-ever clean host, Setup creates
and validates the root-owned evidence directory **before** advancing the
provisioning generation; no precreated `/etc/mcp-gateway` namespace is assumed.
Each newly created privileged directory and its ancestors are fsynced before
persistent provisioning; existing ancestors are also re-fsynced on retry if
an earlier attempt was interrupted during the parent-directory barrier.
No SSH Unix account is created until the root-owned evidence namespace and
its generation/journal state can be durably recorded.

Exact staged files use Linux anonymous `O_TMPFILE` in their own protected
parent directory and atomic no-clobber `linkat` publication, followed by a
parent-directory fsync. Interrupted unpublished inodes disappear without
leaving named `.relay-setup-*` artifacts; a retry re-fsyncs any exact existing
published file and directory after an interrupted link. This requires a
filesystem supporting `O_TMPFILE` and accessible Linux `/proc/self/fd`;
unsupported hosts fail closed before claiming readiness (and before `useradd`
when journal publication is unsupported). Any unrelated or previously
created temporary-looking files remain untrusted and are **never** purged by
prefix; such a host state requires explicit investigation.
The root-only `retire` command also
supports a Setup interrupted **before** `.managed.json` was committed: an
exact journal authorizes only a verified staged unit, pinned key materials
and an exact one-rule nftables ACL; an unknown resource is preserved and
rejected. Full or partial retirement verifies the original journal-bound
numeric SSH UID (and generation marker), including after the key directory
disappears, **before** attempting `userdel`; a recreated same-name account
with a different UID is never deleted. The journal remains until final
service/firewall/key/account cleanup is independently verified. Key files
are removed in a crash-recoverable order, with the private key last.
A managed claim **without** a Setup journal never authorizes cleanup of a
possibly still-present dedicated SSH Unix account or unverified key files:
the helper checks NSS and refuses any residual account or nonempty ambiguous
key namespace **before** stopping the unit or mutating the firewall. An
existing journal-backed account must first be retired with its exact saved
UID; no successful cleanup receipt may conceal an orphaned identity.
Legacy managed-only resources without a dedicated account or credential
content remain retireable via the existing Gateway-only path. For crash
durability, each credential unlink fsyncs its directory; removing the
credential directory fsyncs its parent. Unit/persistence/managed-claim
deletions, then Setup-journal deletion, each fsync their parent namespace.
The journal is retained until dependent resource/account cleanup has been
durably recorded. Before the final retired generation is recorded, all affected unit, private
credential-parent and evidence namespaces are fsynced once more even on a
retry that finds earlier file paths already absent. The final retired generation
and retirement receipt are then written atomically with file and directory
fsync barriers. If interrupted,
the exact recorded generation and remaining resources are verified again on
retry; no unverified identity is adopted or false receipt issued.
Retirement then emits the normal Gateway-only cleanup receipt and supports
the existing Delete/Rotate seal contract. It never contacts intermediary. Incomplete
or unknown host state is retained for explicit operator investigation, not
removed by generic purge.

**NO READINESS IS ISSUED.** Neither a staged service nor even
`GATEWAY LOCAL POLICY AUDIT PASS` proves an isolated production FPM/CLI
UID, allowed/denied intermediary forwarding egress, authenticated SSH/SFTP/WordPress
Target traffic, reboot persistence or a trusted 11-field lease. The Owner
must independently arrange intermediary-side offline enrollment and permitted
egress, complete positive/negative host tests, and obtain a separately
approved trusted readiness issuer before enabling. Do not run source
unpublished host commands on Production; deployment and operational host
modifications require separate Owner authorization.

## Offline intermediary public-key handoff (merged source; no intermediary mutation)

After the independently authorized Gateway host operator completes `setup-gateway`, the
Owner may run the exact release-pinned, read-only `public-enrollment` command shown in
**System > Connection Relays > Stage / repair Gateway host resources**. It prints
only this Relay's verified Ed25519 **public** control key, immutable record ULID,
control endpoint and dedicated intermediary account name in the operator terminal;
**no private key is sent to PHP, displayed by the Admin page, copied to intermediary
or written to logs by this helper**. A root-owned current-generation UID journal,
matching key pair and credentials, authentic local account marker and the
shared lifecycle lock are required. **A surviving managed claim, Setup journal
and public/private key pair are NOT enough:** a read-only host check must also
find the root-owned staged systemd unit with its exact journal/claim digest,
the loaded, unmodified OpenSSH ExecStart with no foreign drop-ins or pending
daemon-reload, a service that is inactive and disabled, the exact root-owned
nftables persistence file, and the currently loaded `inet` table with both
the claimed digest and the reviewed IPv4/IPv6 loopback UID-deny rule. Any
missing, foreign, drifted, partially retired, unexpectedly activated or
fenced state is refused **before any public key is printed**. The export only
queries state (systemctl show/is-active/is-enabled; nft -j list); it never
runs daemon-reload, installs/restores ACLs, restarts a unit, creates an
identity, writes evidence, or issues readiness. For a recoverable interrupted
Setup or missing ACL, use the separate, explicitly authorized Setup/Retry
procedure; for interrupted Retirement, finish Gateway-only Retirement/Seal.
Never present a stale public key for intermediary enrollment.

This handoff is **not intermediary enrollment**. The operator must separately install
and restrict the public key on the specifically authorized intermediary host, with a
dedicated key-only forwarding principal, effective SSHD forwarding limits and
independently verified destination/port egress policy. Where Internet access
is blocked, carry only the public text over a trusted offline channel. Validate
positive and negative egress with the real account and host policy before
operator-controlled activation and separately privileged readiness issuance.
Gateway-only retirement and metadata deletion must continue to work without
contacting intermediary. No production host operation is approved by this source
candidate.

## Offline Relay peer public-identity staging (V2; no SSH admission)

**This helper does NOT enroll an SSH login or enable a Relay.** The offline
resources/host/connection-relay-peer.py script stages only the **public**
Ed25519 identity exported by the reviewed Gateway public-enrollment action.
Use it only after separately authorized host maintenance; the source is not
a published release or an installed host service. The intermediary needs no connection to
Gateway, GitHub or a foreign CDN.

The operator transfers two items over an independently trusted offline channel:
(1) the exact, complete, public-only **11-line v2** Gateway operator-terminal
export as a plain-text file, and (2) the reviewed intermediary helper source from
the same approved repository revision. The v2 export binds the immutable
record ULID to its current configuration revision, configuration fingerprint,
Gateway host generation, public key and intermediary control endpoint/user. An older
eight-line export is deliberately refused rather than silently adopted.
These fields provide **exact identity binding, not cryptographic authenticity
or a signed freshness guarantee**: the operator must obtain the export from
a verified current Gateway session and independently recheck its revision
before any future live enrollment. **Never run the transferred Python file under
sudo or use a split checksum/execute procedure in a writable transfer
directory.** Only an expressly authorized intermediary host operator may perform the
following installation and execution. This is **not** an automatically invoked
installer, live SSH enrollment, or permission to change Production.

For this peer helper, the exact reviewed-source SHA256 is:
A previously installed geography-specific or v1 helper is **not** overwritten by the first-install
procedure. If v1 staging files or an installed v1 helper exist, suspend its
use and obtain a separately approved, source-pinned migration/cleanup plan;
the new helper must not silently adopt or destroy old staged evidence. Earlier
`/var/lib/mcp-gateway-iran-relays` state and the earlier operator installation
path are left untouched by the new generic `/var/lib/mcp-gateway-relay-peers`
namespace; absence of the new path does not prove the old path is empty.

    a0d1fb3a12c98f35a41d60f1e55c562c75ec5ad20f5531e12e7e8b326b72eb7b

**First install only**, from the directory containing the transferred public
source file (the file may be untrusted; it is never executed there):

    /usr/bin/sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C /usr/bin/bash -c '
    set -euo pipefail
    umask 077
    source=$1
    expected=a0d1fb3a12c98f35a41d60f1e55c562c75ec5ad20f5531e12e7e8b326b72eb7b
    base=/usr/local/libexec
    directory=$base/mcp-gateway-relay-peer
    destination=$directory/connection-relay-peer.py
    trusted_dir() {
        test -d "$1" && test ! -L "$1" &&
        test "$(/usr/bin/stat -c %u -- "$1")" = 0 &&
        test -z "$(/usr/bin/find "$1" -maxdepth 0 -perm /022 -print)"
    }
    for parent in / /usr /usr/local; do
        trusted_dir "$parent" || { echo "Unsafe root-owned ancestor" >&2; exit 1; }
    done
    if test -e "$base" || test -L "$base"; then
        trusted_dir "$base" || { echo "Unsafe libexec directory" >&2; exit 1; }
    else
        /usr/bin/install -d -o root -g root -m 0755 -- "$base"
    fi
    if test -e "$directory" || test -L "$directory"; then
        trusted_dir "$directory" &&
        test "$(/usr/bin/stat -c %a "$directory")" = 700 ||
            { echo "Unsafe dedicated helper directory" >&2; exit 1; }
    else
        /usr/bin/install -d -o root -g root -m 0700 -- "$directory"
    fi
    test -f "$source" && test ! -L "$source" ||
        { echo "Transferred source must be a regular non-symlink" >&2; exit 1; }
    test ! -e "$destination" && test ! -L "$destination" ||
        { echo "Existing helper is never overwritten; use a reviewed upgrade" >&2; exit 1; }
    temp=$(/usr/bin/mktemp "$directory/.relay-peer-helper.XXXXXXXX")
    trap "/usr/bin/rm -f -- $temp" EXIT
    /usr/bin/install -o root -g root -m 0500 -- "$source" "$temp"
    printf "%s  %s\n" "$expected" "$temp" |
        /usr/bin/sha256sum --check --status ||
        { echo "Copied source SHA256 mismatch; installation refused" >&2; exit 1; }
    /usr/bin/ln -- "$temp" "$destination"
    /usr/bin/sync -f "$destination"
    test "$(/usr/bin/stat -c %u "$destination")" = 0 &&
    test "$(/usr/bin/stat -c %a "$destination")" = 500 &&
    printf "%s  %s\n" "$expected" "$destination" |
        /usr/bin/sha256sum --check --status ||
        { echo "Installed source verification failed" >&2; exit 1; }
    echo "Root-owned, hash-verified intermediary public-only helper installed; no SSH admission."
    ' bash "$PWD/connection-relay-peer.py"

If the destination already exists, **do not overwrite it** or run a version
upgrade implicitly. Inspect its provenance and use a separately reviewed
upgrade procedure. Installing from a source candidate requires the normal
review/release and operator-authorization gates.

**For each action**, define this wrapper in the authorized operator's shell
and invoke it below. The wrapper revalidates the root-owned ancestor chain and
dedicated file, opens a pinned descriptor, hashes **that descriptor**, then
executes those exact bytes with isolated Python imports. Even if the pathname
changes after opening, Python runs the originally verified inode. Do not
replace this with a direct sudo Python call.

    relay_peer_public() {
      /usr/bin/sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C /usr/bin/bash -c '
      set -euo pipefail
      expected=a0d1fb3a12c98f35a41d60f1e55c562c75ec5ad20f5531e12e7e8b326b72eb7b
      directory=/usr/local/libexec/mcp-gateway-relay-peer
      destination=$directory/connection-relay-peer.py
      trusted_dir() {
          test -d "$1" && test ! -L "$1" &&
          test "$(/usr/bin/stat -c %u -- "$1")" = 0 &&
          test -z "$(/usr/bin/find "$1" -maxdepth 0 -perm /022 -print)"
      }
      for parent in / /usr /usr/local /usr/local/libexec "$directory"; do
          trusted_dir "$parent" ||
              { echo "Untrusted helper path" >&2; exit 1; }
      done
      test "$(/usr/bin/stat -c %a "$directory")" = 700 &&
      test -f "$destination" && test ! -L "$destination" ||
          { echo "Missing or untrusted installed helper" >&2; exit 1; }
      exec 9< "$destination"
      test "$(/usr/bin/stat -Lc %F /proc/self/fd/9)" = "regular file" &&
      test "$(/usr/bin/stat -Lc %u /proc/self/fd/9)" = 0 &&
      test "$(/usr/bin/stat -Lc %a /proc/self/fd/9)" = 500 &&
      test "$(/usr/bin/stat -Lc %d:%i /proc/self/fd/9)" = "$(/usr/bin/stat -Lc %d:%i "$destination")" ||
          { echo "Installed helper inode/ownership changed" >&2; exit 1; }
      printf "%s  /proc/self/fd/9\n" "$expected" |
          /usr/bin/sha256sum --check --status ||
          { echo "Opened helper SHA256 mismatch" >&2; exit 1; }
      exec /usr/bin/python3 -I /proc/self/fd/9 "$@"
      ' bash "$@"
    }
    relay_peer_public stage --input "$PWD/gateway-public-export.txt"
    relay_peer_public inspect --input "$PWD/gateway-public-export.txt"
    # Optional offline public-stage rollback only:
    relay_peer_public retire --input "$PWD/gateway-public-export.txt"

On unsupported Linux filesystems lacking O_TMPFILE and
linkat(AT_EMPTY_PATH), retirement must fail closed **before deletion**; it
must not fall back to a visible, partially written retirement marker.

The public export is parsed with its exact Relay ID, immutable record ULID,
configuration revision, host fingerprint, generation, control endpoint,
control username and wire-validated Ed25519 key. It is public data, **not a
cryptographically signed freshness certificate**. Obtain it directly from a
trusted, current Gateway operator session; never accept an unverified third-
party replacement or assume an old export remains current after Relay
rotation. No private key should ever be transferred to intermediary.

Stage stores exactly control_key.pub and owner.json, both inside a
root-owned 0700 directory at
/var/lib/mcp-gateway-relay-peers/<record-ULID>/, keyed by the immutable
record rather than the display name. A per-record root-owned lock serializes
staging, inspection and retirement. Repeat with identical identity is
idempotent; changed revisions, host fingerprints, host generations, endpoints,
keys, foreign files, symlinks and unsafe ownership refuse without adoption
or cleanup. Existing inert v1 records cannot be migrated or automatically
retired with v2 proof; if any were installed, preserve their exact earlier
export and use a separately approved version-pinned offline cleanup procedure
before staging a replacement. Never treat deletion of a local v1 stage as
proof that a live intermediary identity was revoked. An interrupted retirement uses
an exact durable retiring.json marker and can resume removing only the two
owned public artifacts. If publication was interrupted after linkat but before
a successful directory fsync, retry revalidates the existing marker's exact
content, trusted inode and parent and fsyncs both marker and stage directory
*before* unlinking any public artifact; failed synchronization refuses deletion.
Unexpected incomplete staging or a pending directory is intentionally **not**
recursively deleted: inspect the exact root-owned
namespace before any separately approved recovery.

No Linux SSH principal is created, no authorized_keys or sshd configuration
is installed or reloaded, no listener, service or nftables policy is enabled,
and no privileged readiness evidence is produced. The actual intermediary account
**must be exclusive to the Relay**, not a reused shared SSH principal, and
its AllowTcpForwarding, key-only restrictions and public-destination egress
policy must still be independently installed, positively and negatively
tested, and linked to a fresh Gateway/host generation before any forwarding
activation. The next host-admission/attestation step must not treat a staged
public key as proof of intermediary connectivity, restricted egress or authenticated
Target access. Gateway-only deletion does not depend on intermediary-side staging or
cleanup.

## Gateway-local privileged policy audit (merged source; not installed)

After a separately authorized host provisioning procedure creates root-owned
Relay resources, the Admin disclosure **Audit installed Gateway-local policy
(read-only)** provides a Relay/revision-bound command. It uses the same
release-SHA256-verified privileged executable and shared installation lock as
retirement; it neither provisions a service nor renews readiness evidence.
Do not run it on Production before a separately approved host maintenance
window and verified helper install/upgrade. An installed helper from the
previous source requires the explicit reviewed upgrade procedure below.

The operator command uses the current web PHP effective UID, not a
user-editable value. It acquires the Relay lifecycle lock in shared mode
(refusing overlapping Setup/Retire/Seal) and requires:

- A root-owned v2 resource claim, current unfenced generation, exact immutable
  Relay identity/revision, root-owned unit definition, and matching *effective*
  systemd ExecStart. A Delete fence permanently blocks this record; a Rotate
  fence blocks its own and older revisions, while allowing a separately
  verified newer configuration revision.
- An exact, reviewed OpenSSH argv contract. The service must use
  `/usr/bin/ssh -F /dev/null -N -T` with explicitly pinned non-interactive,
  host-key, no-proxy and credential settings, and exactly ONE dynamic forward
  bound to `127.0.0.1:<reserved-relay-port>`. The endpoint/port/user from
  the root-controlled v2 `owner.json` must agree with that command. No
  additional forwarding modes, command options or public listening sockets
  are accepted even when the unit and effective-command digests agree.
- One dedicated non-root SSH Unix principal named
  `mcp-relay-<first-20-hex-of-SHA256(record-ULID)>`, different from PHP UID.
  The actual NSS-resolved UID, canonical account, non-login shell and live
  OpenSSH process UIDs must agree. The verifier checks existing root-owned
  sibling Relay principal reservations and refuses reused UIDs/principals,
  unsafe/unverifiable siblings or NSS aliases. The local listener inventory
  must contain exactly one socket owned by this systemd MainPID and only at
  this Relay's IPv4 loopback port; unrelated services' other ports remain
  untouched.
- A root-owned private control key (0600), bounded Ed25519 public key,
  root-owned verified key/known-host material and v2 `owner.json` including
  content SHA256 for private key, public key and known_hosts. The helper also
  derives the public key with the pinned local `ssh-keygen -y` and verifies
  that it matches the claimed public key. Unknown files, aliases or corrupted
  keypairs fail closed; the private key is never shown to PHP.
- The effective nftables `inet` table must have exactly one
  `output_guard` output base chain (priority -150, policy accept) and exactly
  one scoped reject rule: outgoing loopback TCP to the reserved SOCKS port
  is rejected for socket UIDs other than the designated Gateway PHP UID.
  IPv4 and IPv6 share this rule. A matching digest cannot justify an extra
  rule rejecting the designated UID, an unrecognized jump/drop/return,
  unexpected priority, foreign chain or policy.

This strict one-rule check proves only the *owned Relay table's* semantics,
not system-wide positive connectivity: another firewall table or a separate
host firewall can still deny the approved UID. Real IPv4/IPv6 positive and
negative socket tests and FPM/CLI/sibling-site UID isolation are separate
host-acceptance requirements, not inferred from this source-level audit.

Output is **GATEWAY LOCAL POLICY AUDIT PASS** or actionable **FAIL CLOSED**.
Passing this check is deliberately NOT a readiness lease. The helper creates
no policy marker or eleven-field readiness manifest and cannot itself set a
Relay Ready/Enabled. Separate effective verification of the dedicated
Gateway PHP-FPM/CLI UID and sibling-site isolation, intermediary forwarding-only
control account and permitted egress, SSH control connectivity, and actual
Target authentication remains required. Setup, Update, Repair, trusted
attestation issuer and real-host end-to-end acceptance are still unfinished.

Root-only SSH private keys cannot be read by the unprivileged SSH service
directly. A future host Setup must deliver `control_key` and `known_hosts`
via trusted systemd `LoadCredential=`, into the service-specific
`/run/credentials/<unit>/` directory used by the audited argv. Do not weaken
root-only storage or assume systemd dynamic credential paths are verified
without on-host checks. Synthetic audit fixtures do not prove working SSH
transport or credential delivery.

## Gateway-local retirement procedure (merged source, not deployed)

The reviewed helper source is shipped with the normal release and update
payload at `resources/host/connection-relay-gateway.py`. Its exact SHA256 is
pinned in `config/connection_relays.php`. Updating the web app does NOT
install or execute the privileged helper. The Owner must separately
authorize the host change and compare the displayed digest against a
**trusted release artifact**, not just the same web UI.
The operator cleanup command first attempts an **exact current privileged Seal**:
when the matching permanent fence/receipt already exists, it renews that
proof without re-retirement. If Seal cannot certify the current revision,
it runs exact Gateway-only resource retirement followed by Seal. Merely
finding a fence file is **never** enough to skip retirement; a previous
rotation fence can coexist with newly provisioned resources at a later
revision. Any failed retirement or Seal leaves the record disabled/recoverable
and never authorizes DB deletion or rotation.

The helper source was revised for exact N+1-to-N retirement support. The
Cleanup/bootstrap command **never** replaces an installed executable, even
one from a known older release. An older helper fails the current release
SHA256 check until the Owner separately runs the **Explicit verified helper
upgrade** command (under the collapsed installation/diagnostics section).
The upgrade permits exactly one pinned predecessor digest, recorded in
`config/connection_relays.php` as
`gateway_retirement_helper_upgrade_from_sha256`. For the proposed v2 source
candidate this is the helper integrated through PR #293; older/unknown
binaries are **not** accepted by a one-step upgrade. A separately approved,
version-pinned transition is required if a host actually has an earlier helper.
The exact predecessor may be replaced with the current release-pinned source
only after the source bytes are copied to an isolated root-owned temporary
inode and the copy matches the new SHA256.
**Before upgrading a helper installed by an older release, enter a controlled
operator maintenance window.** Pause all Gateway Relay host operator
workflows; stop issuing historic copy/paste commands and let **all** already
issued old command and sudo sessions finish before proceeding. Prevent anyone
from starting another historic command until upgrade completes. Merely
checking that no helper process is currently visible is insufficient: an old
shell might have passed SHA256 verification but not yet executed the helper.
After upgrade, discard old command copies, refresh the Admin page, and use
only newly generated commands. If the operator cannot positively control
old command admission and drain, **do not upgrade**. The old commands have no
installer lock and cannot be retroactively protected by new PHP code.

The installer obtains an **exclusive** root-owned lock at
`/run/mcp-gateway-relay-helper-install.lock`; every newly generated
`/usr/bin/sudo /usr/bin/bash -c` host-operation command obtains a
**shared** lock at that exact path **before** checking the helper SHA256,
and holds the same lock through the helper's exit. Thus a cooperating Upgrade
cannot replace the executable between digest verification and execution, and
concurrent Relay operations still use their separate scoped per-Relay
lifecycle locks. This installer lock is **not** a cross-invocation lifecycle
transaction: each `retire`, `seal-delete` or `seal-rotate` invocation
acquires/releases it independently. A non-cooperating older command or a
privileged out-of-band mutation remains outside this guarantee; the
maintenance window controls the former, and trusted-host boundaries
govern the latter.

Under its exclusive lock, Upgrade rechecks the exact predecessor digest
and uses an atomic same-directory rename. It never adopts unknown, tampered,
linked, non-executable, unsafe-permission or third-party helper files. Both
the installer and newly issued operator commands require a root-owned
executable of the expected `0755` mode. Already-running processes keep their
original inode; a successfully executed Upgrade is idempotent on the
current hash. The previous helper code is recoverable from its reviewed
GitHub commit, but the installer does not silently roll back. Compare both
old and new expected digests against a trusted release artifact and obtain
separate host-operator approval before running. Do not bypass the digest
check to force an upgrade. No host update occurs when this code is merged.

1. Disable the selected Relay, reconcile and explicitly detach/reassign all
   Targets; never silently fall back to Direct. Open **Retire and remove Relay**.
2. Copy the **one cleanup-and-seal-for-delete command** and execute it with approved
   sudo access **only on the Gateway host**. It verifies an already installed
   exact release-pinned helper; if missing, it first copies the source into
   a root-owned temporary inode, SHA256-checks the copied bytes and atomically
   publishes it. An unknown, stale, linked or unsafe installed tool causes
   an explicit refusal. No existing binary is overwritten. If a known older
   helper is installed, run the separate **Explicit verified helper upgrade**
   command first, verify the installed SHA256 and then retry Cleanup.
3. The command first attempts an exact-current `seal-delete` using
   the release-pinned privileged helper. If the current permanent fence and
   retired generation already match, Seal **renews the receipt only**; no
   repeat retirement is needed. Otherwise the command runs exact Gateway-local
   `retire` followed by `seal-delete`. **Each privileged CLI invocation**
   independently verifies the installed helper digest and acquires/releases
   the same per-Relay exclusive root lock; the two separate invocations are
   **not one continuously locked transaction**. A host generation or resource
   change between them makes the subsequent Seal fail closed, requiring
   operator reconciliation and retry, not an assumed success. Separate
   bootstrap and preflight commands remain available for diagnostics.
   The arguments identify the Relay ID, DB ULID, current configuration
   fingerprint/revision and local port (plus the exact prior fingerprint for
   scoped retirement after Disable), never SSH private keys or Target credentials.
4. The helper locks and validates the exact root-owned Relay namespace.
   It stops only a matching claimed systemd service, removes only the
   claimed nftables table and key files, clears local readiness evidence,
   and verifies there is no remaining local service, loaded same-name
   systemd unit (even inactive), listener or named firewall table.
   A foreign unit discovered after daemon-reload blocks the receipt and
   preserves the managed resource claim for safe diagnosis/retry. Unknown
   resources, unsafe ownership/symlinks, active listeners and failed
   operations are rejected instead of purged.
   No SSH connection to intermediary is attempted.
5. On the **first successful cleanup**, `retire` issues a root-owned,
   boot-bound retirement receipt (600-second lease) after verifying removal
   of the exact Gateway resources; `seal-delete` verifies that clean host,
   commits the permanent per-record deletion fence and renews the receipt.
   Expected first-run output includes **RETIREMENT VERIFIED**, then
   **LIFECYCLE FENCE VERIFIED (delete)**. On an idempotent retry with a
   valid **current** Seal, the command skips retirement and renews the
   receipt, outputting only **LIFECYCLE FENCE VERIFIED (delete)**. A stale,
   foreign or historical rotation fence is never sufficient to skip cleanup.
   Refresh Admin. With no bound Targets, exact ID, Owner password, Owner
   acknowledgement and a current matching fence + receipt, the DB record
   can be deleted. An offline intermediary host NEVER prevents this.
   Cleanup of old intermediary-side accounts/keys is optional and independent.

### Generation invalidation: mandatory BEFORE new Setup or Repair

The privileged helper now maintains a **root-owned, non-secret**
`/etc/mcp-gateway/connection-relays/<relay-id>.generation.json` containing
exactly `version=1`, DB `relay_record_id`, `relay_id`,
`host_generation` (fresh 64-character random hex) and
`state=provisioning|retired`. Its file mode is 0644 for the isolated,
unprivileged PHP reader. Retirement rotates this generation to
`retired` **before** issuing a matching receipt, under the per-Relay
root lock. PHP requires BOTH the retired proof and matching current
retired generation, and refuses any present active `.managed.json`,
`.policy` or `.json` file even with an unexpired old receipt.

**Current application-side readiness hardening:** PHP now requires the complete,
root-owned v2 `<relay-id>.managed.json` claim and the v1
`<relay-id>.generation.json` record in addition to the existing eleven-field
host evidence and `<relay-id>.policy` marker. The active generation MUST be
`provisioning`, belong to the **exact database record ULID**, and match the
claim, the current Relay fingerprint, configuration revision, reserved port,
expected scoped systemd unit/table identities, and the policy marker. A
retirement receipt, invalid/foreign generation/claim, permanent deletion fence,
or stale rotation fence makes the Relay **not ready**. An older rotation fence
may coexist only with a strictly newer configuration revision and a different
host generation. This closes replay of a legacy/manual lease after
`prepare-setup`, rotation or record-ID reuse; it does **not** attest effective
OS controls on its own. Future privileged Setup and verifier must use the
current generation token as the published policy marker and must replace it
under the same per-Relay root lock after policy changes, never forge an
attestation from Gateway PHP. Previously issued manual evidence without a
matching owned v2 claim and generation cannot enable the route. No automated
installer/verifier or real-host claim issuance is delivered by this hardening.

**Every future privileged Setup/Repair/reprovision must execute**
`prepare-setup` with the exact Relay identity, revision and port
**before any host resource is created**, and check the permanent per-record
fence before changing generation or resources. This action locks the Relay,
proves existing resources are absent, rotates its generation to
`provisioning` FIRST, then removes the old receipt. A crash between
these steps remains fail-closed. Future installer/repair code must hold
the same root lock while creating resources, and its v2 managed claim
must carry that new provisioning generation. It may not reuse an old
retired generation or create resources before invalidating proof.
**No Setup/Repair feature is delivered in PR #286**; this is an explicit
host-generation protocol boundary for the next implementation package.

The retirement receipt is **non-secret metadata** and is issued
root-owned, mode 0644, so the non-root Gateway PHP-FPM identity can read
it. Newly created evidence paths are root-owned, mode 0755, while the
lock directory and keys remain private. Existing root-owned evidence
parents that are not PHP-searchable are **not chmodded by the helper**:
the operation refuses to claim success and the operator must decide
how to reconcile directory access.

**Owned resource contract — v2, fail-closed:** The root-owned
`/etc/mcp-gateway/connection-relays/<relay-id>.managed.json` contains
exactly `version=2`, `relay_record_id`, `relay_id`,
`service_unit`, `firewall_table`, `local_socks_port`,
`host_fingerprint`, `configuration_revision`,
`host_generation`, `unit_sha256`, `unit_exec_sha256`
and `firewall_sha256`. Its generation must match a root-owned
`provisioning` state. Older or unproven v1 claims are refused, not
silently adopted.

Systemd unit:
`mcp-gateway-relay-<relay-id>.service` at
`/etc/systemd/system/<service-name>` with exact root-owned
`# MCP-GATEWAY-CONNECTION-RELAY <record-ULID> <relay-id>` marker and
claimed SHA256 bytes. Before `disable --now` the helper verifies
effective `systemctl show` identity and `FragmentPath`, no
drop-in/transient configuration, `NeedDaemonReload=no`, and matching
SHA256 of the immutable `ExecStart` executable path, arguments and
`ignore_errors` value. The helper deliberately excludes volatile
systemd-reported start/stop timestamps, PID and last exit status, so a
legitimate restart cannot invalidate a correct unit identity. The future
installer must hash this same canonical representation. A foreign
same-name unit is never stopped. An interrupted removal after the owned unit disappeared is
recoverable only when the loaded but inactive old definition still
matches the expected path and `ExecStart`, followed by
successful `daemon-reload`.

Dedicated nftables inet table:
`mcp_gateway_relay_<first-12-hex-sha256-of-record-ULID>`.
Before removal, the helper parses the **full**
`nft -j list table inet <name>` JSON, validates exact
table/chain/rule ownership, removes only volatile `handle`
and `metainfo` fields, serializes stable sorted JSON and compares
SHA256 to the root-owned claim. The future Setup helper must use this
exact normalization algorithm when recording the claim. Unknown,
modified or unprovable rules are never removed; table name is
insufficient proof. The helper rechecks policy immediately before
deletion and preserves ACLs while a listener remains open.

The root-owned key namespace is
`/var/lib/mcp-gateway-relays/<relay-id>`, restricted to the known
files. Other Relays, Reverse SSH, and unknown host resources are not
modified. Privileged local testing and prerequisites `systemctl`,
`nft` and `ss` still need distinct real-host authorization.

**Editing:** immutable Relay IDs cannot be rotated in place; create a new
Relay and intentionally migrate Targets. Changing endpoint, host key,
username or local port requires fresh local retirement proof AND a `rotate`
fence for the old configuration before the PHP update. Rename display name without any host command or downtime.
After an identity edit the old retirement proof no longer validates the
new configuration. The Setup/Update and short-lived independent readiness
attestation implementation are still outstanding.

Tests of this helper currently use disposable directories and fake
`systemctl`, `nft` and `ss`; those tests are **not a claim of
production host, systemd, firewall or intermediary setup verification**.

### Evidence-bounded Admin operational states (merged source; not deployed)

The Admin listing classifies each registration without a blocking TCP/SSH probe:
**Draft** means the initial application registration is not host-attested (it
does not prove that external host files are absent); **Needs setup** means a
later disabled revision has no current readiness proof; **Ready** means a
disabled registration has current independent host evidence; **Enabled** means
the route was deliberately enabled and host evidence remains current;
**Degraded** means an enabled registration has stale/missing evidence or an
unexpected terminal deletion fence; **Cleanup required** means an inactive
registration has a durable deletion fence and awaits proof renewal or final
metadata removal. Each state displays a concrete next action. These
application-facing labels neither install resources nor assert SOCKS
availability, intermediary reachability, or end-to-end Target authentication.

## User workflow

1. Open **System > Connection Relays**. Register stable Relay ID, display name, intermediary control SSH endpoint and independently verified *public* SSH host key, dedicated user and reserved Gateway local SOCKS5 port (46000–60999). The metadata is saved disabled, without changing hosts.
2. Obtain separately authorized host setup. The privileged operator provisions dedicated identities, daemon and ACL below. Only the *public* client key may be sent to the intermediary; private keys stay out of the web root and logs. Perform isolation/egress/host-key tests before the operator signs a root-owned attestation.
3. Enable with the Owner password. The app rejects missing or stale attestation and does not claim remote connectivity. The optional control listener test checks only that SOCKS5 responds.
4. On **Targets > Add Target**, choose SSH or WordPress connector, then optionally a ready Relay, and confirm Owner password. For SSH, choose Direct rather than Managed/Manual Reverse. Authenticate/test the actual Target separately.
5. On Target Edit, change route only after disconnect and reconciliation. The Owner/password-gated workflow increments a persistent route epoch and re-seals SSH login secret. WordPress requires no active OAuth credential/flow/refresh/revoke intent. A->B->A cannot reactivate historical retained SSH Jobs.
6. Disabling a Relay fails closed and fences every bound Target. Repair/reenable does not silently declare Targets Connected.

## Required separate Gateway host approval

The previously inspected Gateway deployment shared one PHP-FPM Unix UID with several other websites. A loopback-only SOCKS5 listener is **not isolated** in this arrangement. Approval to use this feature must include a deployment-specific host change plan and rollback. In order:

- Give Gateway its own dedicated non-root PHP-FPM pool and UID, not shared with any unrelated website or the SSH control client. Its PHP CLI scheduler/queue must run with the same appropriately isolated identity, or dedicated owner-verified equivalent to avoid failed route attestations. Verify real process credentials, application paths and permissions; retain safe return to previous PHP pool. Do not weaken other sites.
- Create a distinct low-privilege SSH client identity, Ed25519 control key in root-controlled non-web directory, pinned independently obtained intermediary SSHD public host key, and supervised systemd client connecting Gateway -> intermediary using sessionless OpenSSH dynamic local SOCKS5. Use BatchMode, IdentitiesOnly, StrictHostKeyChecking, ExitOnForwardFailure, ServerAlive, and a fixed bind of 127.0.0.1:port only. Do not edit the current dedicated Reverse SSHD instance or its port.
- Extend the **existing** nftables/iptables/aaPanel firewall with narrowly owned rules: only the dedicated Gateway PHP UID can connect to this exact loopback port; unrelated UIDs are denied. An output-chain socket UID condition is an implementation possibility, **not an approved production command**. Prove the actual firewall order, IPv4/IPv6 scope, persistence and rollback before use. Reject or drop access from all unrelated site Unix identities, even if they can open localhost TCP sockets. Do not turn off the host firewall to simplify setup.
- Verify in different *actual OS identities* that Gateway PHP can connect and unrelated websites cannot; allow the root-owned attestation path, `/proc/sys/kernel/random/boot_id` and `/proc/uptime` through any effective PHP open_basedir policy without relaxing other filesystem restrictions; ensure rules survive daemon restart/reboot and are enforced before the SOCKS client starts. Check a downed tunnel fails without Direct, without opening public listeners.

## Required separate intermediary host approval

Install a dedicated non-root, public-key-only SSH control user, no shell/TTY/password/sudo, agent/X11/StreamLocal forwarding or unrelated authorized keys. Require SSH local forwarding only; validate effective sshd settings and relevant per-key policy with the actual OpenSSH build. Dynamic -D connects via direct-tcpip. PermitOpen applies to fixed destinations, but shared future Target routing may require several hosts and ports. Therefore restrict this principal using an independently approved intermediary host/network egress policy to the intended TCP ports and public IP space, denying loopback, RFC1918, link-local, metadata, multicast, local and reserved addresses. Test permitted and denied cases, concurrency, restart and log fidelity. Gateway public-IP SSRF policy is mandatory second-layer validation, not a substitute for host ACL.

Intermediary setup must not require the intermediary server to download a script from Gateway or an external CDN. Use an independently available transfer path for approved code/public keys, with pinned checksum and provenance. Never store Relay private keys, password or opaque credentials in GitHub issue comments, web forms or normal diagnostic logs.

## Root-owned readiness evidence

The Admin backend validates **four** required root-owned artifacts for each Relay. They must all belong to the same exact record ULID and active configuration:

    /etc/mcp-gateway/connection-relays/<relay-id>.generation.json  (v1)
    /etc/mcp-gateway/connection-relays/<relay-id>.managed.json     (v2)
    /etc/mcp-gateway/connection-relays/<relay-id>.policy           (current generation token)
    /etc/mcp-gateway/connection-relays/<relay-id>.json             (11-key readiness lease)

The verifier also checks whether `<relay-id>.retired.json` exists (which rejects readiness) and inspects the optional root-owned `.fences/<record-ULID>.json`. **A missing fence is accepted only after the PHP identity positively enumerates the trusted parent directory and, if present, `.fences`; an inaccessible directory is not evidence of absence.** A visible deletion fence rejects readiness permanently for that record, while a valid older `rotate` fence is permitted only for a strictly newer revision and different generation. Recheck the fence and generation after the rest of the read. These PHP checks are not a replacement for the privileged helper's exclusive lifecycle lock.

All four artifacts and their parent directories must be root-owned, non-symlink, not group/world writable, and actually accessible to the effective Gateway PHP UID. The evidence directory and optional `.fences` directory must be **readable and searchable** (or the Relay fails closed); the private key and lock directories must **not** be opened to PHP. A root-owned `0700` `.fences` directory with a concealed fence is explicitly unsafe: reconcile operator permissions rather than interpreting it as an empty directory. The `.policy` file contains the **same fresh 256-bit generation** as the `provisioning` v1 record, never an independently invented token. Before any FPM/CLI identity, service, SSH principal, firewall, routing, egress or binding policy change, a privileged helper must invalidate the old generation under the same exclusive root-only lock used for the entire Setup/Repair lifecycle. Post-change effective OS checks must finish before an independent privileged verifier issues/renews the lease; PHP writes none of these artifacts.

Merged main provides the **source-side validator, retirement/fence helper and staged Gateway-local Setup/Retry resources**. Neither these merged resources nor the proposed v2 public-key export issue/renew authoritative readiness, enroll or restrict the intermediary SSH principal, or prove a live end-to-end Target path. A syntactically valid root-owned claim is not proof of actual SOCKS, intermediary reachability or Target identity.

The manifest has exactly **11** keys (illustrative schema, not real values; never copy as-is). **Existing 10-key manifests are invalid and must be reissued by the independently privileged operator**; do not migrate or extend them automatically:

    {
      "relay_id": "edge-relay-1",
      "host_fingerprint": "<current 64-hex configuration fingerprint>",
      "gateway_php_uid": 1001,
      "dedicated_php_uid_verified": true,
      "socks_access_acl_verified": true,
      "relay_egress_verified": true,
      "verified_boot_id": "<current /proc/sys/kernel/random/boot_id UUID>",
      "policy_generation": "<identical 64-hex content of relay-id.policy>",
      "verified_at_unix": 1793822400,
      "verified_at_boot_seconds": 135000,
      "expires_at_unix": 1793865600
    }

The operator records `verified_at_boot_seconds` **at the same verification moment** as `verified_at_unix`, using the integer part of the first value in Linux `/proc/uptime`; this is a boot-relative clock **including suspend time** ([Linux `proc_uptime(5)`](https://man7.org/linux/man-pages/man5/proc_uptime.5.html)). The verifier must obtain the sample on the **Gateway host**, not on the Relay peer or in a container with an incompatible boot/uptime view. Both timestamps must be observed only after effective host isolation is independently verified; do not fill them from unchecked assumptions. The manifest is accepted only while the actual PHP effective UID matches, the running Linux boot ID and policy generation match, the boot-relative age is non-negative and strictly under 86400 seconds, its Unix expiry is strictly in the future and within 24 hours of verification, and Unix versus boot-relative elapsed ages differ by no more than 60 seconds. Large wall-clock forward/backward jumps invalidate the evidence rather than extending the lease. Readable `/proc/uptime` and a valid 11-key schema are mandatory; missing or invalid sources fail closed. The privileged verifier must regularly re-check the effective host controls and renew the manifest **before** expiry; no PHP action may silently renew or infer that effective firewall enforcement is intact. A reboot always invalidates the prior boot's manifest. Independent host configuration drift must trigger policy rotation and re-verification even if the short lease has not yet expired; **static file checks alone cannot detect unreported host drift**.

`host_fingerprint` is generated by `ConnectionRelay::hostFingerprint()` from the immutable Relay identity, endpoint, control key, local port and `configuration_revision`, separated with NUL bytes; it is **not** a login-key fingerprint. Every effective Enable or Disable advances the separate monotonic `lifecycle_revision` used by Owner action forms, invalidating prepared Enable/Disable requests after any intervening action. Each effective Disable also advances `configuration_revision` and atomically fences bound Targets, invalidating the old host manifest. **This does not imply that the prior host resources have been removed:** the approved Gateway-only `retire` command may prove an exact v2 claim against the current DB revision N+1 **or** its immediately preceding provisioned revision N, using an explicit expected prior fingerprint deterministically calculated from the unchanged connection fields. It never adopts arbitrary older or foreign claims. Under the same Relay-scoped root lock, the helper positively verifies and removes those exact installed resources, then issues the retirement receipt for the **current** N+1 fingerprint and revision. `seal-delete` / `seal-rotate` accept **only** the current revision, so the permanent fence agrees with the DB transition. A partial failure retains the claim for bounded Retry. The optional prior fingerprint is accepted by read-only `preflight` and `retire` only; it grants no Setup or Seal privilege. Intermediary reachability remains irrelevant.

Enable does **not** change the attested configuration fingerprint; the independently verified manifest remains current for the same unchanged host policy until expiry. Re-enabling after a Disable requires new privileged verification and a new manifest matching the current configuration fingerprint. A repeated Disable while already disabled is a no-op only with the latest lifecycle revision. No production host setup, verifier implementation, attestation or socket supervision is provided by this application source; the host operator owns their separate approval, persistence, exact host policy and recovery.

## Acceptance, diagnostics and rollback

- Record three separate states: saved/disabled or enabled, host attestation and local SOCKS greeting, then successful end-to-end Target authentication. A SOCKS greeting alone cannot greenlight an SSH/WordPress Target.
- Validate real Target SSH host-key mismatch before login; HTTPS TLS hostname and SNI; DNS rebinding/non-public DNS refusal; denied egress; request size/deadline; retained Job and stale OAuth outcome fencing; reconnection/reboot; multiple simultaneous Targets.
- A failed/missing Relay blocks only its selected Targets, with a specific diagnostic and no Direct fallback. Do not auto-retry effectful remote operations after uncertain dispatch.
- Rollback: disable Relay via Owner UI first to fence Target epochs; independently verify pending Job/OAuth outcome reconciliation; stop only that Relay's controlled service; remove only positively owned host firewall rules, identity, key and attestation under separate authorization. Do not roll back DB columns while historical epoch-bound Target entries or retained SSH Jobs exist.
- **Gates:** full source diff + exact-head CI + independent high-assurance review; separate authorized Gateway/intermediary host preflight, rollout and real end-to-end tests; explicit Owner merge/deploy approval. No production claim before those facts exist.
