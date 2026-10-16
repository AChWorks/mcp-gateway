# Direct SSH Target Connector

**Scope:** Runtime and operator contracts for the implemented **`ssh_direct`** Target family, including verified host-key/login, bounded non-interactive commands, SFTP, optional full-file HTTPS and shipped v2.3.0 detached Jobs. Effective defaults depend on the installed release and Owner settings; optional whole-file transfer is OFF when its effective configuration is false. Real ChatGPT file/attachment ingestion and production-host configuration are independently unverified. Historic releases and acceptance belong to GitHub Releases/Issues, not a continually appended pre-release ledger.
Parent: [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106).
See also [Target foundation](./TARGET-CONNECTOR-FOUNDATION.md), [remote I/O contract](./REMOTE-IO-CONTRACT.md).

## Released v2.1.2: Owner operations and permission UI

In public v2.1.2, Target details → Edit Target separates display name from
Owner-only/password-confirmed connector configuration. SSH registered host,
TCP port, username, independently verified **server public host key**, and
the **write-only** password/private-key/passphrase can be changed without
removing the Target or its User/Target Group references. Existing encrypted
login material is re-encrypted against the new exact endpoint/pin binding
when retained; a method change requires a fresh password/private login key.
The new key must parse with its supplied passphrase. Any real change
clears the old verified connection/observed peer and forces **Verify SSH
host and login** again before SSH commands or SFTP can run. In-flight
old verification results and stale Owner forms are fenced; no change to
remote OS users, keys or active remote sessions is implied.

An older, not-yet-upgraded host may still display SSH under "Review reserved
permission definitions". That is an installed-version mismatch, not a statement
about the public v2.1.2 source. The corrected source renders three **active** SSH capability
checkboxes (command run, SFTP read, SFTP write) with **checked = DENY**,
not a future/reserved label. Add User starts with all three checked and may
apply explicit Owner-confirmed **Selected Target scope** grants at creation;
normal unreviewed callers stay default-denied. Edit User and User → Target
access permit audited, Owner-confirmed deliberate SSH ACL changes. Target
Group controls are live deny-only rules; they cannot grant shell authority
without the role, global grant and selected Target. SSH command permissions
enable general shell/file access even when SFTP toggles deny file tools.
The previously proposed Agent connector was canceled by the Owner; its stored type and historic denial-seeding compatibility were retired in #182. Only WordPress and Direct SSH are supported and no Agent capability is advertised.

These capabilities are shipped with v2.1.2, **not evidence that a particular
operator host has been upgraded or its optional route enabled**. The sections
below describing immutable bindings document the historical initial SSH slice;
current Owner-controlled rotation supersedes that older immutability rule.

## Integrated command slice: bounded SSH exec (PR #145)

The integrated `ssh-command-run` tool authorizes exactly one stored `target_id` through `ssh.command.run`, and reuses the existing verified numeric peer, pinned server host key and encrypted Target-bound credential before a one-off, non-interactive exec. It does not authorize an arbitrary destination, install a daemon, or change WordPress operations. Remote shell text is not allowlisted. The selected remote OS account alone determines permitted commands, including `sudo`, root and access to remote files.

The shipped v2.2.1 command limits are 1–15 seconds with at most 8192 UTF-8 input bytes. v2.3.0 retains those defaults while adding Owner-adjustable maximum execution timeout (15–30 seconds) and command input budget (8–64 KiB) in the **existing** Operational Settings store. Commands longer than the current Owner limit reject with actual effective-limit diagnostics. Each MCP tool manifest publishes the per-request maximum, with actual byte length checked server-side (JSON Schema `maxLength` counts characters). Changes take effect for new requests without restarting services. Synchronous command processing still depends on the installed PHP/proxy/client deadlines: use a retained SSH Job for longer tasks; a 30-second exec cap is not a guarantee that every hosting stack can sustain that request. Captured stdout is limited to 16384 bytes, stderr to 8192 bytes, with independent UTF-8 or base64 representations, nullable exit status, completeness/truncation markers and the verified connection IP. A timeout, channel failure, or exceeded preview budget after possible dispatch is `outcome_unknown`; the command is never retried automatically, and no continuation/resume is invented. The remote process may continue after disconnect, so a caller must not repeat a mutating command without independent verification. Activity records do not include raw command strings or output.

SSH command rights remain denied by default for non-owners. An Owner must explicitly confirm a selected-scope SSH permission change while reauthenticating. Disabling future `ssh.file.read` or `ssh.file.write` SFTP tools cannot contain remote file access by an account granted unrestricted `ssh.command.run`. Bounded SFTP was integrated separately in #146, and Owner-controlled host-key/credential rotation later shipped via PR #168. Command exec was merged as #145 after independent review; safe Owner-controlled rotation subsequently shipped in v2.1.2.

## v2.3.0: lightweight agentless SSH Jobs (#181)

**Not available on prior v2.2.1 installations; a public Release does not upgrade an operator host.**
This source adds four ordinary OAuth-authenticated MCP Tools alongside
synchronous `ssh-command-run`. It does **not** install or depend on AI Server
Agent, a Gateway queue daemon, Redis, PTY or an IDE runtime.

| MCP tool | Parameters and result |
| --- | --- |
| `ssh-job-start` | Exact `target_id`, caller-generated UUID `request_id`, UTF-8 `script` up to 16 KiB, `max_runtime_seconds` 16–the current Owner maximum (default max 300 seconds, Owner-adjustable up to seven days; default request 60 seconds); returns a stable 26-character `job_id`, status and retry guidance |
| `ssh-job-status` | Exact `target_id` and `job_id`; reconciles remote exit marker or authenticated systemd active state; `failed` includes actual exit code when a script marker is readable; systemd failures have an explicit reason without a fabricated exit code. If systemd reports `exit-code` first and a bounded SFTP read cannot obtain the marker, a later status poll can recover the numeric exit without re-running the job |
| `ssh-job-output` | Job ID and `stdout` or `stderr` with bounded 1–16 KiB Base64 window, explicit offset, size and EOF; use multiple reads without re-execution |
| `ssh-job-cancel` | Best-effort stop of the exact unit; only reports `canceled` after independently verifying inactive/failed state and no live MainPID/ControlPID; otherwise `cancel_requested` is honest |

A Job requires **all three existing SSH permissions** (`ssh.command.run`,
`ssh.file.read`, `ssh.file.write`) to start, plus a connected exact SSH
Target and previously approved verified host key/OS account. Subsequent
operations require the same authenticated Gateway user, OAuth client profile
and exact persisted Target binding, and the relevant live operation grants.
Job scripts and output are not stored in the Gateway database, logs or
analytics: the encrypted Target credentials are used only inside the existing
SSH/SFTP runtime. The Gateway stores a durable random job ID and hashed
identity/script/Target binding *before* any remote side effect. The same
`request_id` and identical arguments return the same job; changed parameters
fail rather than trigger a second execution. A lost post-dispatch response is
`outcome_unknown` / `launch_unknown` and **must never be launched again**.

Supported remote execution requires Linux `systemd-run` and a persistent
systemd **user** manager with `loginctl enable-linger` already approved by
that host's operator, or a root-owned system manager when the deliberately
configured SSH OS account is root. Missing support fails closed before
staging. The same verified SSH path creates one remote private `0700`
directory under `/var/tmp/.mcp-gateway-job-<job_id>`, stages both the script
and wrapper via existing atomic SFTP single-window writes (mode `0600`),
and launches a transient `systemd-run` unit (failed units retained until safe cleanup) with finite lifetime,
file-size and control-group constraints. The wrapper writes bounded
`stdout`, `stderr` and a durable exit-code marker. A job may outlive the
browser session or Gateway PHP request; each later poll creates an
independently authorized new SSH connection. Systemd service availability
is a *remote host capability*, not guaranteed on shared hosting.

A user has **no cumulative historical Job-count limit**. The Owner controls
the maximum **simultaneously admitted** Jobs per user (default 2, supported
1–1024) and maximum runtime of each new Job (default 300 seconds, configurable
300–604800 seconds, i.e. seven days) in **Admin → Operational Settings →
Detached SSH Jobs**. These are two separate resource boundaries: the MCP
`ssh-job-start.max_runtime_seconds` schema exposes the current effective
Owner ceiling, and the remote systemd unit enforces the runtime selected for
that Job. An existing Job keeps its original finite runtime/lease even if
the Owner later changes limits. Total stored Job history does not count
against concurrency.

The Owner separately controls terminal-result retention (default 24 hours,
1–8760 hours), the crashed pre-dispatch `preparing` recovery threshold
(default 120 seconds, 30–600), and the conservative post-runtime admission
grace (default 600 seconds, 60–3600). Each new Job snapshots its
pre-dispatch cutoff and selected reconciliation grace in immutable journal
fields, independent of later Owner settings changes. At the exact
`preparing -> launch_unknown` CAS, the admission lease is floored to cover
a conservative 360-second remote mkdir/SFTP preparation window plus up to
90 seconds for bounded systemd dispatch, the Job's requested runtime and
its snapshotted reconciliation grace. Immediately before the possibly
effectful `systemd-run`, another exact-status/active-lease check **extends,
never shortens**, admission to cover the latest possible dispatch, actual
remote runtime and original grace. An unexpectedly stalled start whose
existing lease already expired must NOT run systemd-run: a different Job
could already have taken its slot. Neither renewal nor expiry implies
remote completion. After the correctly computed admission deadline,
an uncertain `launch_unknown`, `running` or `cancel_requested` Job
no longer occupies a concurrent admission slot.
**Lease expiry does not prove remote completion, issue a cancellation,
unlock a retry, or delete any script/output.** Its original user, client,
Target binding, script digest, request UUID and Job ID remain stored for
inspection/reconciliation. Each new Job also snapshots its original user ID,
Target record/public ID, hostname, port, OS username, authentication method,
and SHA-256 digest of the pinned host-public-key line in separate immutable
(non-foreign-key) journal fields. This metadata is NOT a password, private
key, remote-connection grant or script log. It survives later User/Target
deletion or binding rotation and can identify the original endpoint for
operator verification. Older pre-migration records are backfilled only when
their current stored Target binding still matches exactly; otherwise the
original endpoint is reported **unknown** rather than misattributed to a
replacement host. A duplicate request UUID remains idempotent
for as long as its journal is retained.

A crash in `preparing` is different: that state is *before* the first
possible remote side effect. Both new admission attempts and the hourly
`gateway:ssh-jobs-prune` scheduler may mark a provably stale `preparing`
as `failed` with `terminal_reason=pre_dispatch_abandoned`; the
in-flight PHP probe must win an exact conditional state transition before
it may stage or launch anything. The expired pre-dispatch record can be
pruned without contacting a remote host. Genuine remote-uncertain records
are **never auto-pruned**, even if their admission lease or result-retention
timestamp is past. Ordinary terminal entries are retained for the configured
period **after reaching terminal state**. Remote spool cleanup remains
restricted to named files inside an independently verified same-owner,
non-symlinked `0700` directory.

**Exception recovery for the actual deployment operator:** an authorized
local operator with access to the installed Gateway Artisan CLI may inspect
the immutable no-replay journal without any remote operation:

```bash
php artisan gateway:ssh-jobs-reconcile inspect
php artisan gateway:ssh-jobs-reconcile inspect YOUR_EXACT_26_CHARACTER_JOB_ID
```

If the original user/Target was deleted, access revoked, or the Target
binding/SSH account rotated, automatic spool removal intentionally refuses
to connect to a potentially **different** host. First identify and
independently verify the **original** remote systemd unit is stopped and
the **original** remote private Job spool has actually been deleted.
Do **not** infer that from admission expiry, a missing/newly bound Target,
an SSH timeout, or a successful cancellation request alone. After that
verification, an authorized *local deployment operator* can explicitly
attest the cleanup, supplying the exact stored original 64-character
Target-binding SHA-256 from `inspect`, exact Job ID twice, and a meaningful
reason. `inspect` shows the immutable original non-secret host/port, OS
login and host-key digest even after referenced user/Target deletion; its
original host-key digest is only a checksum of the stored pinned public key,
**not a substitute for verifying the original host out-of-band**. Older
pre-snapshot records without trustworthy provenance need independent
operator evidence before attestation:

```bash
php artisan gateway:ssh-jobs-reconcile retire YOUR_EXACT_26_CHARACTER_JOB_ID \
  --confirm=YOUR_EXACT_26_CHARACTER_JOB_ID \
  --binding=ORIGINAL_64_CHARACTER_BINDING_SHA256 \
  --reason="Verified original systemd unit stopped and original spool removed" \
  --attest-remote-cleaned
```

The CLI is **not** an unauthenticated MCP/browser action. It never performs
SSH itself, never resumes or dispatches a script, and refuses to retire a
nonterminal entry until its conservative admission lease has elapsed.
It records `status=retired` and `terminal_reason=operator_attested_cleanup`,
the local OS UID, reason, and timestamp; this is an **operator assertion**,
not a verified remote exit code. The original immutable journal fields
remain intact for the Owner-configured retention period before the hourly
scheduler can delete only the now-attested local record. Normal
`completed`/`failed`/`canceled` evidence is distinct from `retired`.
After every journal row is safely reconciled and pruned, guarded schema
rollback is possible; never manually drop the table or bypass the
migration safety guards. For the current exact operation, inspect
`gateway:ssh-jobs-reconcile --help` before any attestation.

**Acceptance evidence and boundary:** A disposable GitHub Actions
runner passed actual systemd-user SSH execution >15 seconds with real exit
code 7, bounded stdout/stderr, replay resistance, cancellation and cleanup
(18 assertions), followed by a no-linger fail-closed check (5 assertions)
in [historical CI #38774916531](https://github.com/AChWorks/mcp-gateway/actions/runs/38774916531).
The prior rc.5 lease-safety and MariaDB same-user race evidence belongs to
[historical PR #187 checks](https://github.com/AChWorks/mcp-gateway/pull/187/checks),
not the current release candidate. The subsequent rc.7 correction and pause
gates were independently approved and merged via
[PR #190](https://github.com/AChWorks/mcp-gateway/pull/190); the
[stable promotion PR #188](https://github.com/AChWorks/mcp-gateway/pull/188)
requires its own exact-head CI and independent review. The official manual
release workflow additionally binds publication to the approved **merged main SHA**,
not an old PR number. The real disposable test is in
`tests/Feature/Mcp/SshJobFixtureTest.php` and runner-only
`tests/Support/ssh-job-ci-fixture.sh`; it is not proof of every production
systemd/SSH host shape. No test alters an operator Target or production SSH service.

## SFTP file I/O — released in v2.1.2

The v2.1.2 release includes PR #146's stat, bounded list, binary-safe ranged read and bounded small write MCP tools. Each requires exact Target ID, fresh pre-login Gateway authorization, verified numeric SSH peer, pinned server host key before credential login and fresh post-login Target/permission checks. The file tools have independent read or write Gateway permissions, default denied for nonowners until a password-confirmed explicit Owner grant in Selected scope. The remote SFTP subsystem and Unix account determine path/symlink/chroot behavior. SSH shell command authority remains independent and can still read or modify remote files.

Directory lists cap at 100 entries and 16 KiB of names; overflow errors instead of inventing a cursor. Range reads cap at 16 KiB, encode opaque bytes in base64, expose EOF/size/mtime, and optionally compare size+mtime before and after a range. Size+mtime is only a best-effort change detector, NOT a strong unchanged-source proof. Small inline writes cap at 16 KiB. Create-only (default) uses verified private sibling staging and OpenSSH exclusive hardlink publication; a server without that extension fails closed instead of replacing an existing destination. Explicit `overwrite=true` replaces an existing regular file through the server's atomic POSIX-rename extension without requiring size/mtime, while preserving the previous file permissions. Optional paired `expected_size` and `expected_mtime` provide a best-effort preflight comparison, **not atomic compare-and-swap**; concurrent authorized replacements are last-writer-wins. Staging remains private before writing nonempty bytes and remote content is verified before publication. No unknown-result mutation is blindly retried. The 16 KiB inline ceiling is not the whole-file transfer ceiling; large streaming work is separately tracked.

For SFTP, the SSH TCP DNS policy resolves both A and AAAA records through an isolated async React DNS loop with one monotonic deadline shared by DNS, TCP, verified login and SFTP operations. Queries use only the system-configured DNS servers; no external DNS provider or synchronous libc lookup is used for the bounded SFTP path. The complete answer set still undergoes public-IP validation, followed by an exact numeric TCP dial, peer check and pinned host-key check before sending credentials. Expired lookups cancel outstanding queries and return a typed timeout before the 90-second SFTP Target admission lease expires. Hosts lacking usable OS resolver settings fail closed. Direct SSH command DNS remains on its separately governed existing system policy; do not claim this change adds command-specific admission deadlines.

The locked phpseclib 4.0.2 SFTP client has a shell exec fallback when the SFTP subsystem is refused; the integrated SFTP path explicitly rejects this fallback. Unsupported SFTP must never become implicit shell execution. No generic terminal, arbitrary URL/host routing, public filesystem endpoint or mandatory background daemon is introduced.

Optional authenticated raw-binary **HTTP** upload/download now composes the existing streams in [PR #166](https://github.com/AChWorks/mcp-gateway/pull/166), with a separate, finite SSH-only whole-file budget and independent client byte/SHA-256 proof. It remains **OFF by default** in public v2.1.2. Strict immutable remote snapshots, durable interrupted-transfer recovery and private/VPN destination approval remain outside this file-I/O implementation. Owner-controlled Target endpoint/credential rotation shipped in v2.1.2; do not call bounded Base64 MCP payloads streaming or imply any production installation.

## Internal SFTP byte streams — shipped in v2.1.2, not a standalone public endpoint

[PR #148](https://github.com/AChWorks/mcp-gateway/pull/148) was reviewed as a stacked child of [PR #146](https://github.com/AChWorks/mcp-gateway/pull/146); both are included in the v2.1.2 release. Its internal `SshFileRuntime::downloadToStream()` and `uploadFromStream()` move binary data between already-staged local streams and authorized SFTP Targets. The **internal runtime alone** is not a public tool, HTTP upload/download endpoint or ChatGPT file handoff. The separately authenticated [#147/PR #166 sidecar](WHOLE-FILE-EXCHANGE.md) now uses it for actual client↔SSH file bytes in a disposable installed test, without claiming native ChatGPT model consumption. No release or deployment is implied.

**Safety and cost:** Reuse the parent's shared SFTP frame, request-ID and response-buffer budgets (maximum 256 KiB per response frame, 2 MiB/64 frames per completed batch), authenticated identity, and monotonic socket/operation deadline. The internal stream operation supplies a validated 1–40 second budget within the 90-second admission lease, and sends source data in 64 KiB blocks instead of buffering a whole file in PHP. Only seekable local regular streams are accepted; no raw sockets, arbitrary stream wrappers or unbounded request bodies. A caller-controlled maximum byte count is enforced. Reads validate length, best-effort source metadata and optional SHA-256; callers must discard any partial sink after failure.

**Writes:** The caller must provide an existing same-filesystem remote staging directory owned by its SFTP principal and restricted to 0700. Each upload checks its new zero-byte inode's ownership, applies 0600 and verifies privacy **before** writing nonempty bytes; length and SHA-256 are verified through remote readback. Create-only publishing uses an exclusive OpenSSH hardlink; explicit `overwrite=true` uses atomic POSIX replacement of an existing regular file, preserving its previous file mode. Optional paired size/mtime checks are best-effort before publication, **not atomic CAS**; concurrent authorized overwrites may be last-writer-wins. After uncertain mutations, return `outcome_unknown` and never blindly retry. Staging cleanup remains best-effort on interruption.

The separately OAuth-authenticated full-file client ingress/egress shipped in v2.1.2 through PR #166 (disabled by default), but native ChatGPT model-readable output, host-specific quotas and actual operator deployment remain separately gated in #147/#112.

## Product boundary

`ssh_direct` is a **separate, built-in Target connector** for explicitly registered Linux/Unix SSH servers **without requiring an additional remote management agent**. It supports username/password and username/private-key (+ optional passphrase) authentication. The user selects the remote OS account; the server's account permissions determine actual command privileges, including `sudo` and root when that account is legitimately configured for them.

**Do not impose a Gateway command allowlist, hardcoded command/`sudo`/root denial, or shell-text filtering masquerading as a security boundary.** Arbitrary commands are mutation-capable. Gateway authorizes the *capability* to run commands on the *selected Target*, not individual shell strings. Warnings and a clear high-privilege label may assist operator choice but must not claim containment.

This does **not** authorize anonymous or cross-user access. Gateway user/client authentication, Target scope, explicit operation permissions, encrypted credential custody, verified SSH server identity, egress/network safety, finite resource bounds and audit remain mandatory. A user who explicitly grants full OS privilege accepts the consequences for that Target.

The Gateway remains a routing/control plane. No generic application-wide arbitrary HTTP/shell endpoint, raw proxy tunnel, SSH client supplied arbitrary host/port, or command execution in the Gateway's installer/updater.

## Verified destination identity and operator routing

A Direct SSH Target identifies a **registered server and chosen remote OS principal**. Gateway's immutable `target_id` is always the selection/authorization key; IP address and hostname are useful human context, **never standalone authority**. Display a scoped identity such as `display name — deploy@203.0.113.10:22 — target-id`, with bracketed IPv6 and explicit verified/unknown/stale last observed peer state as appropriate. Similar IPs with distinct ports/users/Targets remain separate; inventory/search must not make an outbound connection or leak unauthorized host details.

For each admitted remote action, resolve the registered endpoint under the actual SSH egress policy, validate its numeric resolved/dialed **TCP peer**, verify the Owner's independently trusted, pinned **SSH server public host key before sending any login secret**, then authenticate using the encrypted Target-bound OS credential. Unknown/mismatched host key, unsupported cryptography, unsafe DNS/peer identity and changing binding must fail closed. The transport's modern cryptographic policy excludes fallback to known-weak SHA-1-only host-signature/KEX/MAC/ciphers. A fresh out-of-band verified host-key rotation is an explicit Owner action, not autoacceptance. No SSH agent forwarding, secret reuse across Targets or user-supplied arbitrary host override.

Production direct SSH destinations are governed by actual current configured TCP egress policy. **Do not claim private/VPN Target support exists until a reviewed scoped network policy is integrated and tested.** A plausible future private-network mode is not permission to relax current SSRF/peer/host-key protections or turn Gateway into a network scanner.

## Shell, SFTP and Job behavioral distinctions

- **One-off command** runs as the configured remote OS account in a fresh non-interactive exec context. Shell directory/environment state does not persist across calls. An unavailable exit code, truncated stdout/stderr or lost response is not proof the command failed or is safe to rerun. OS-configured non-interactive `sudo` may work; an interactive PTY/password prompt is not automatically supported.
- **SFTP** stat/list/ranged read/small write is a separate permission-gated file interface and must fail if the actual SFTP subsystem is unavailable; never silently fall back to phpseclib shell execution. File path/symlink/ownership and root semantics belong to the remote OS account. Precondition size/mtime checks are best effort, **not atomic remote CAS**.
- **Whole-file HTTPS/SFTP** is a separately authenticated client-supported mode with its own actual enabled flag, byte/time budgets and remote staging/integrity proof. An inline SFTP call window is not a whole-file-size limit. Requiring a model to inspect a file demands separately proven client handoff, not merely a server path.
- **Detached SSH Jobs** are actually shipped in the v2.3.0 release and can outlive one PHP request where the remote server supports the selected systemd model. See the Job section above. [PR #196](https://github.com/AChWorks/mcp-gateway/pull/196) proposes independently adjustable Job script size; **the published/main default remains 16 KiB until that candidate is integrated and released**. Job idempotency/unknown launch, active concurrency lease and verified cancel constraints must not be replaced by “retry command” logic.
- **No universal SSH prohibition by command string:** granting `ssh.command.run` grants arbitrary OS-account shell rights; SFTP Tool denials do not contain that shell. Accurate Owner permissions, exact Target identity and measured finite resource limits protect the Gateway boundary; the downstream OS limits ultimate privilege.

This is the operator/connector technical contract for **integrated supported SSH behavior**, not a checklist of retired initial slices. Historical login-only, pre-SFTP and pre-Job development/CI decisions remain in Git history and completed [#123](https://github.com/AChWorks/mcp-gateway/issues/123), [#181](https://github.com/AChWorks/mcp-gateway/issues/181) and related immutable PRs. For current delivery use actual Releases/host evidence; for future file receipt use [#147](https://github.com/AChWorks/mcp-gateway/issues/147), effective budgets [#154](https://github.com/AChWorks/mcp-gateway/issues/154) and safe diagnostics [#199](https://github.com/AChWorks/mcp-gateway/issues/199). No production SSH operation is authorized by this document.
