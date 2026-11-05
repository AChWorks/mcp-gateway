# Connection Relays — owner/operator runbook (Issue #284)

**Core Relay routing source is merged, but this capability has not been published or accepted on real hosts.** The Gateway-host-only privileged retirement/fencing helper is merged as source but has not been installed or verified on a real host; initial setup, update/reprovision and independent readiness attestation are still unfinished. Production host setup, firewall edits, SSH identity creation, installation, migrations, integration and release require distinct approvals and verification. A saved Relay alone does not mean a tunnel is running or that the actual Target is authenticated.

## Intent and architecture

Connection Relay is a reusable per-Target transport route, not a third connector, a per-Target tunnel, a generic HTTP proxy or a VPN. Direct remains the default. Existing Managed and Manual Reverse SSH remain intact and cannot be combined with the new Relay for the same SSH Target.

    Gateway dedicated PHP-FPM UID -> 127.0.0.1:<relay-SOCKS-port>
    -> restricted Gateway OpenSSH client -D -> Iran restricted SSH control user
    -> validated numeric public Target IP:port
    -> end-to-end SSH host-key pin or HTTPS TLS SNI and certificate check

Each Relay requires one control-plane SSH identity/key completely distinct from the Target login credential and the existing Reverse SSH control identities. The Gateway performs bounded public DNS and numeric destination approval locally, sends only numeric SOCKS5 CONNECT, preserves the real SSH Target host key or HTTPS certificate, and never treats the SOCKS reply as verified remote peer identity. No automatic fallback to Direct. Only deliberate Target operations use a relay; ChatGPT signed-file ingress and unrelated Gateway services remain Direct.

## Unified Create / Edit / Delete lifecycle (required product acceptance; not yet delivered)

Gateway is the **unprivileged control plane**, not a root-level package manager. Its user journey must offer one cohesive lifecycle for multiple independently managed Relay resources:

| Owner action | What Gateway may do | Privileged host action and proof |
| --- | --- | --- |
| Create | Save an inactive draft and prepare a scoped, easy-to-copy Setup instruction | Prepare dedicated UID/ACL, SSH identity, keys and supervised listener; constrain Iran principal/egress; independently verify both sides; issue root-owned short-lived readiness evidence |
| Rename | Change only the display name with Owner reauthentication and optimistic revision check | **No host command**, no connection interruption or Target epoch reset |
| Edit host, port, key, username, identity or local listener | Disable/detach Targets, require verified root-owned `rotate` fence for the old revision before DB commit | **Gateway-only cleanup + `seal-rotate` under the same root lock as Setup**; old revision cannot be provisioned after fencing; only a newer revision can proceed to future Setup/attestation |
| Disable or diagnose | Fail closed for explicitly bound Targets and show distinct host/control/Target status | Host service changes require a reviewed privileged action; no implicit Direct fallback |
| Delete | Require explicit Target detach/reassignment, disable, Owner confirmation, fresh exact-registration cleanup receipt **and irreversible `delete` fence** | **Scoped cleanup + `seal-delete` on the Gateway host** permanently forbids any future Setup/Repair for that exact DB ULID, including after DB deletion. No Iran connectivity, remote cleanup, or sibling/Reverse SSH resource change |

The command must be generated for the exact Relay and checked revision; support an independently transferred/offline Iran-side package when Iran cannot fetch code from foreign endpoints. No arbitrary shell construction from form inputs, production root execution by PHP, generic destructive purge or silently claimed success. Failure leaves a recoverable disabled registration with an actionable Retry/Repair. Host resource changes must be idempotent, ownership-scoped and positively verified. A successful response from a script alone is not evidence that the Target was authenticated.

**Interim security boundary:** The application now separates display-only rename from sensitive route changes and forbids hard deletion based on an Owner checkbox or absent attestation file. Final deletion requires Owner acknowledgement, a **privileged, short-lived root-owned Gateway-host cleanup receipt** AND an **irreversible, root-owned `delete` fence** bound to exact DB ULID, Relay ID, fingerprint, revision and host generation. An ordinary receipt alone never authorizes DB deletion or sensitive identity rotation. It does **not** require Iran reachability, remote cleanup evidence or Iranian SSH credentials. The exact-receipt verifier and scoped Gateway-host-only retirement helper were merged in PR #286, but are not installed or operationally accepted. The helper must be installed by the separately authorized host operator; it is NOT a tunnel installer or host-readiness attester. **Do not present Create/Edit/Setup as finished or claim this is deployed.** The UI preserves records instead of fabricating cleanup. This receipt is never to be hand-authored by PHP or fabricated by an operator.

The receipt is located at `/etc/mcp-gateway/connection-relays/<relay-id>.retired.json` (fixed root-owned, symlink-free namespace) and contains exactly `relay_record_id`, `relay_id`, `host_fingerprint`, `configuration_revision`, `host_generation`, `verified_boot_id`, `verified_at_unix`, `verified_at_boot_seconds`, `expires_at_unix`, `gateway_cleanup_verified`. The single boolean must be true **based on independent privileged verification on the Gateway host**. The lease is valid for no more than 900 seconds, with no significant wall-clock/boot-clock divergence. Active policy and readiness files must be gone. There is no Iranian cleanup field or network check: an unreachable Iran server must never prevent Gateway-side deletion after local verification and Owner confirmation. Remote cleanup, if desired, is an optional separate follow-up. Real-host operational acceptance and a distinct setup/update helper are still required before whole-product acceptance.

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

## Gateway-local retirement procedure (merged source, not deployed)

The reviewed helper source is shipped with the normal release and update
payload at `resources/host/connection-relay-gateway.py`. Its exact SHA256 is
pinned in `config/connection_relays.php`. Updating the web app does NOT
install or execute the privileged helper. The Owner must separately
authorize the host change and compare the displayed digest against a
**trusted release artifact**, not just the same web UI.

1. Disable the selected Relay, reconcile and explicitly detach/reassign all
   Targets; never silently fall back to Direct. Open **Retire and remove Relay**.
2. Copy the **one cleanup-and-seal-for-delete command** and execute it with approved
   sudo access **only on the Gateway host**. It verifies an already installed
   exact release-pinned helper; if missing, it first copies the source into
   a root-owned temporary inode, SHA256-checks the copied bytes and atomically
   publishes it. An unknown, stale, linked or unsafe installed tool causes
   an explicit refusal. No existing binary is overwritten.
3. The same command runs `retire`, then `seal-delete` under the same
   helper version and per-Relay root lock. Each privileged invocation
   independently checks the installed helper digest. Separate
   bootstrap and preflight commands remain available for diagnostics. The
   arguments include only
   the Relay ID, DB ULID, configuration fingerprint/revision and local port,
   not SSH private keys or Target credentials.
4. The helper locks and validates the exact root-owned Relay namespace.
   It stops only a matching claimed systemd service, removes only the
   claimed nftables table and key files, clears local readiness evidence,
   and verifies there is no remaining local service, loaded same-name
   systemd unit (even inactive), listener or named firewall table.
   A foreign unit discovered after daemon-reload blocks the receipt and
   preserves the managed resource claim for safe diagnosis/retry. Unknown
   resources, unsafe ownership/symlinks, active listeners and failed
   operations are rejected instead of purged.
   No SSH connection to Iran is attempted.
5. On success, `retire` atomically issues a root-owned, boot-bound receipt
   with a 600-second lease; `seal-delete` verifies the clean host and commits
   a permanent per-record deletion fence, then renews the receipt. Refresh
   Admin. With no bound Targets, exact ID, Owner password, Owner acknowledgement
   and a current matching fence + receipt, the DB record can be deleted.
   An offline Iran host NEVER prevents this.
   Cleanup of old Iran-side accounts/keys is optional and independent.

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
production host, systemd, firewall or Iran setup verification**.

### Evidence-bounded Admin operational states (next candidate; not deployed)

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
availability, Iran reachability, or end-to-end Target authentication.

## User workflow

1. Open **System > Connection Relays**. Register stable Relay ID, display name, Iran control SSH endpoint and independently verified *public* SSH host key, dedicated user and reserved NL local SOCKS5 port (46000–60999). The metadata is saved disabled, without changing hosts.
2. Obtain separately authorized host setup. The privileged operator provisions dedicated identities, daemon and ACL below. Only the *public* client key may be sent to Iran; private keys stay out of the web root and logs. Perform isolation/egress/host-key tests before the operator signs a root-owned attestation.
3. Enable with the Owner password. The app rejects missing or stale attestation and does not claim remote connectivity. The optional control listener test checks only that SOCKS5 responds.
4. On **Targets > Add Target**, choose SSH or WordPress connector, then optionally a ready Relay, and confirm Owner password. For SSH, choose Direct rather than Managed/Manual Reverse. Authenticate/test the actual Target separately.
5. On Target Edit, change route only after disconnect and reconciliation. The Owner/password-gated workflow increments a persistent route epoch and re-seals SSH login secret. WordPress requires no active OAuth credential/flow/refresh/revoke intent. A->B->A cannot reactivate historical retained SSH Jobs.
6. Disabling a Relay fails closed and fences every bound Target. Repair/reenable does not silently declare Targets Connected.

## Required separate NL host approval

The inspected NL Gateway host shares one PHP-FPM Unix UID with several other websites. A loopback-only SOCKS5 listener is **not isolated** in this arrangement. Approval to use this feature must include a deployment-specific host change plan and rollback. In order:

- Give Gateway its own dedicated non-root PHP-FPM pool and UID, not shared with any unrelated website or the SSH control client. Its PHP CLI scheduler/queue must run with the same appropriately isolated identity, or dedicated owner-verified equivalent to avoid failed route attestations. Verify real process credentials, application paths and permissions; retain safe return to previous PHP pool. Do not weaken other sites.
- Create a distinct low-privilege SSH client identity, Ed25519 control key in root-controlled non-web directory, pinned independently obtained Iran SSHD public host key, and supervised systemd client connecting NL -> Iran using sessionless OpenSSH dynamic local SOCKS5. Use BatchMode, IdentitiesOnly, StrictHostKeyChecking, ExitOnForwardFailure, ServerAlive, and a fixed bind of 127.0.0.1:port only. Do not edit the current dedicated Reverse SSHD instance or its port.
- Extend the **existing** nftables/iptables/aaPanel firewall with narrowly owned rules: only the dedicated Gateway PHP UID can connect to this exact loopback port; unrelated UIDs are denied. An output-chain socket UID condition is an implementation possibility, **not an approved production command**. Prove the actual firewall order, IPv4/IPv6 scope, persistence and rollback before use. Reject or drop access from all unrelated site Unix identities, even if they can open localhost TCP sockets. Do not turn off the host firewall to simplify setup.
- Verify in different *actual OS identities* that Gateway PHP can connect and unrelated websites cannot; allow the root-owned attestation path, `/proc/sys/kernel/random/boot_id` and `/proc/uptime` through any effective PHP open_basedir policy without relaxing other filesystem restrictions; ensure rules survive daemon restart/reboot and are enforced before the SOCKS client starts. Check a downed tunnel fails without Direct, without opening public listeners.

## Required separate Iran host approval

Install a dedicated non-root, public-key-only SSH control user, no shell/TTY/password/sudo, agent/X11/StreamLocal forwarding or unrelated authorized keys. Require SSH local forwarding only; validate effective sshd settings and relevant per-key policy with the actual OpenSSH build. Dynamic -D connects via direct-tcpip. PermitOpen applies to fixed destinations, but shared future Target routing may require several hosts and ports. Therefore restrict this principal using an independently approved Iran host/network egress policy to the intended TCP ports and public IP space, denying loopback, RFC1918, link-local, metadata, multicast, local and reserved addresses. Test permitted and denied cases, concurrency, restart and log fidelity. Gateway public-IP SSRF policy is mandatory second-layer validation, not a substitute for host ACL.

Iran setup must not require the Iran server to download a script from NL or foreign CDN. Use an independently available transfer path for approved code/public keys, with pinned checksum and provenance. Never store Relay private keys, password or opaque credentials in GitHub issue comments, web forms or normal diagnostic logs.

## Root-owned readiness evidence

The Admin backend reads **two** independently privileged, root-owned files for each Relay:

    /etc/mcp-gateway/connection-relays/<relay-id>.policy
    /etc/mcp-gateway/connection-relays/<relay-id>.json

The parent directories and both files must be root-owned, non-symlink and not group/world writable. The `.policy` file is a single fresh, unpredictable 256-bit generation (64 lowercase hex characters, optional trailing newline). A privileged operator rotates it **before** changing the relevant FPM/CLI identity, service, SSH principal, firewall, routing, egress or binding policy. Host operations must fail closed until post-change verification and renewed evidence. Neither file is written by the Gateway PHP process.

The manifest has exactly **11** keys (illustrative schema, not real values; never copy as-is). **Existing 10-key manifests are invalid and must be reissued by the independently privileged operator**; do not migrate or extend them automatically:

    {
      "relay_id": "iran-1",
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

The operator records `verified_at_boot_seconds` **at the same verification moment** as `verified_at_unix`, using the integer part of the first value in Linux `/proc/uptime`; this is a boot-relative clock **including suspend time** ([Linux `proc_uptime(5)`](https://man7.org/linux/man-pages/man5/proc_uptime.5.html)). The verifier must obtain the sample on the **Gateway host**, not on the Iran Relay or in a container with an incompatible boot/uptime view. Both timestamps must be observed only after effective host isolation is independently verified; do not fill them from unchecked assumptions. The manifest is accepted only while the actual PHP effective UID matches, the running Linux boot ID and policy generation match, the boot-relative age is non-negative and strictly under 86400 seconds, its Unix expiry is strictly in the future and within 24 hours of verification, and Unix versus boot-relative elapsed ages differ by no more than 60 seconds. Large wall-clock forward/backward jumps invalidate the evidence rather than extending the lease. Readable `/proc/uptime` and a valid 11-key schema are mandatory; missing or invalid sources fail closed. The privileged verifier must regularly re-check the effective host controls and renew the manifest **before** expiry; no PHP action may silently renew or infer that effective firewall enforcement is intact. A reboot always invalidates the prior boot's manifest. Independent host configuration drift must trigger policy rotation and re-verification even if the short lease has not yet expired; **static file checks alone cannot detect unreported host drift**.

`host_fingerprint` is generated by `ConnectionRelay::hostFingerprint()` from the immutable Relay identity, endpoint, control key, local port and `configuration_revision`, separated with NUL bytes; it is **not** a login-key fingerprint. Every effective Enable or Disable advances the separate monotonic `lifecycle_revision` used by Owner action forms, invalidating prepared Enable/Disable requests after any intervening action. Each effective Disable also advances `configuration_revision` and atomically fences bound Targets, invalidating the old host manifest. Enable does **not** change the attested configuration fingerprint; the independently verified manifest remains current for the same unchanged host policy until expiry. Re-enabling after a Disable requires a new privileged verification and manifest for the new configuration fingerprint. A repeated Disable while already disabled is a no-op only with the latest lifecycle revision. No production host setup, verifier implementation, attestation or socket supervision is provided by this application source; the host operator owns their separate approval, persistence, exact host policy and recovery.

## Acceptance, diagnostics and rollback

- Record three separate states: saved/disabled or enabled, host attestation and local SOCKS greeting, then successful end-to-end Target authentication. A SOCKS greeting alone cannot greenlight an SSH/WordPress Target.
- Validate real Target SSH host-key mismatch before login; HTTPS TLS hostname and SNI; DNS rebinding/non-public DNS refusal; denied egress; request size/deadline; retained Job and stale OAuth outcome fencing; reconnection/reboot; multiple simultaneous Targets.
- A failed/missing Relay blocks only its selected Targets, with a specific diagnostic and no Direct fallback. Do not auto-retry effectful remote operations after uncertain dispatch.
- Rollback: disable Relay via Owner UI first to fence Target epochs; independently verify pending Job/OAuth outcome reconciliation; stop only that Relay's controlled service; remove only positively owned host firewall rules, identity, key and attestation under separate authorization. Do not roll back DB columns while historical epoch-bound Target entries or retained SSH Jobs exist.
- **Gates:** full source diff + exact-head CI + independent high-assurance review; separate authorized NL/Iran host preflight, rollout and real end-to-end tests; explicit Owner merge/deploy approval. No production claim before those facts exist.
