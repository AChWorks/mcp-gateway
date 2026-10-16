# Direct SSH Target Connector

**Release status (v2.1.2):** Direct SSH registration, verified password/key login, arbitrary OS-authorized commands, bounded MCP SFTP tools, internal binary streams, optional OAuth-bound whole-file HTTPS transfer ([PR #166](https://github.com/AChWorks/mcp-gateway/pull/166)), and Owner-confirmed endpoint/credential/permission edits ([PR #168](https://github.com/AChWorks/mcp-gateway/pull/168)) are **publicly released**. Installed binary-capable PHP/Python clients passed in disposable acceptance fixtures, not the real operator host. The optional whole-file route remains **OFF by default**. Native ChatGPT model/attachment file ingestion, private/VPN host egress and operator-host resource capacity remain unverified; publication does not upgrade a server.
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

## Historical initial SSH registration and verified-login slice (pre-release evidence)

The first independent implementation slice added connector-owned `ssh_direct_target_configs` (host/port/username, selected password or private-key authentication, out-of-band pinned SSH **server** public key, last observed verified numeric peer IP with timestamp), encrypted purpose-bound `target_credentials`, an accessible Target registration/inspect/test/disconnect Admin workflow, authorization-filtered IP-inclusive Admin and MCP Target inventory, and `phpseclib/phpseclib` transport code.

The order of operations is mandatory: exact stored `target_id` and Target-scoped Gateway authorization, per-Target bounded connection admission/rate control, registered endpoint validation, bounded public numeric DNS/TCP policy, numeric TCP dial, **actual TCP peer comparison**, cryptographically verified server host key and exact pinned key comparison, **then** password/private-key login. Passwords, login private keys and key passphrases are write-only encrypted data; no incoming request may override the saved destination. A changed/unknown host key fails closed. No DNS or remote calls happen during inventory. The initial registration uses an explicit operator attestation of independently verified host-key material; it never trusts a key merely obtained from the destination. Each admitted login check claims a persisted per-attempt fencing token under a short Target row lock; only the currently claimed attempt may persist success/failure and audit. Superseded attempts cannot overwrite newer outcomes after an admission-lease expiry or delayed state commit. The attempt token is cleared on completion or disconnect; no DB row lock spans DNS/TCP/KEX/login. The SSH transport advertises a Gateway-owned modern KEX/cipher/MAC policy instead of phpseclib's broad compatibility defaults; RSA host pins permit RSA-SHA2 signatures only, while preserving the canonical `ssh-rsa` public-key blob format.

A successful login test authenticates and disconnects without running a command. Last-verified IP/time must not be confused with a live heartbeat; prior observations display as stale when Target connection state is not connected. "Disconnect" removes the **local Gateway SSH credential**, not the remote OS account or other active SSH sessions. This first implementation treated the verified host-key/endpoint binding as immutable; later Owner-confirmed editing and verification fencing shipped in v2.1.2. At the time of this initial login-only slice, arbitrary shell execution, SFTP, streaming, command outcome semantics, private/VPN egress approval and mixed release acceptance **were not yet implemented**. Subsequent source integrations #145 (commands), #146 (bounded SFTP) and #148 (internal streaming) implemented the first three capabilities independently. Optional SSH HTTPS whole-file handoff shipped disabled by default in v2.1.2 via #147/PR #166; **native ChatGPT attachment/model handoff**, private/VPN approval, real-host acceptance and actual deployment remain outstanding. Neither the initial slice nor later source integration is proof of an installed release.

Security tests cover out-of-band host-key pin parsing, encrypted bound credentials, IP-inclusive authorization-filtered inventory, default SSH capability denials, public-only policy, per-Target connection admission/rate control and WordPress regressions. CI also provisions disposable loopback-only OpenSSH fixtures behind an explicitly fixture-only dial-policy implementation; that does **not** relax production `SshTcpAddressPolicy`, which rejects loopback. The fixture covers positive password authentication, encrypted RSA private-key/passphrase authentication with an Ed25519 host pin, RSA-SHA2 host-pin interoperability, wrong-password failure, wrong-host-key rejection before authentication, actual numeric peer verification, and fail-closed legacy-only RSA/SHA-1, weak-KEX, weak-cipher and weak-MAC negotiation. This paragraph describes the historical verified-login fixture. SSH commands (#145) and bounded SFTP (#146) now have their own integrated runtime and regression evidence; external client/file handoff later passed in isolated installed tests; broader interruption recovery and real-host WP+SSH acceptance remain open.

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

## First useful slice

- Admin: register/test/reconnect/disconnect/remove a `ssh_direct` Target; fields include display name and immutable Gateway `target_id`, hostname/IP, port, username, auth method and write-only password **or** private key with optional passphrase. Store encrypted connector-purpose credentials behind #109; never return, log or repopulate secret inputs.
- Identity: pin/verify the expected SSH **server host public key** before sending credentials. First connection requires out-of-band trusted fingerprint confirmation; do not silently accept a newly discovered key as verified. On mismatch fail closed; replacement/rebinding/rotation must be deliberate, not an automatic fallback.
- Commands: stable public `ssh-command-run` tool with required `target_id` and command; bounded optional timeout/input. Execute exactly as the configured OS account, **without a command allowlist**. Return separate bounded stdout/stderr, nullable exit status, completeness/truncation, timing/outcome and safe error codes. One-off non-interactive exec, one request for ordinary commands.
- OS privilege: do not strip `sudo`, reject root usernames, or rewrite operator commands. `sudo -n` can work when the remote OS account is configured for non-interactive elevation. A server-side password/TTY prompt may require a future opt-in PTY/interactive workflow; do not claim the initial exec path can satisfy every interactive prompt. Never auto-inject a stored SSH password into `sudo` stdin.
- Files: bounded SFTP `stat`/`list`/ranged `read` and small `write`, plus ordinary streamed upload/download where compatible with the supported web-host request lifecycle. SFTP support depends on the remote server subsystem and OS account permissions; report absence rather than silently trying a shell-based workaround.
- Gateway permission selectors: `ssh.command.run`, `ssh.file.read` and `ssh.file.write` (and connector access through ordinary Target-scoped permissions). These are independent **Gateway tool exposure** permissions and simple UI toggles, not a sandbox. **If `ssh.command.run` is enabled, a user can run shell commands that read/write remote files regardless of whether the Gateway SFTP tools are disabled.** Never advertise the file toggles as filesystem containment.
- Operator UI can show remote login privilege as informational (regular/sudo/root) and a warning, but an `Allow sudo` toggle would be unenforceable with unrestricted commands. Do not implement a misleading security switch.
- A new connector permission must default to denied for existing **non-owner** users, with explicit Owner-enabled role-ceiling/global-denial and Target-scope assignment as already used in #107/#110. No WordPress role inherits shell privileges on migration.

## IP-inclusive SSH Target identification

**A Direct SSH Target must be distinguishable by its IP address when selected or used, not only by display name or `target_id`.** The Gateway-local `target_id` remains the immutable routing and authorization selector, internal Target record ID remains distinct, and the SSH server host key is the separate cryptographic identity. An IP or hostname alone is not a durable identity or a security boundary.

- **Connector-owned configuration:** save the registered host as a canonical IPv4/IPv6 literal or explicitly registered DNS hostname, TCP port, OS username, auth method and pinned server host key. Store bounded effective connection IP, observation time and verification/freshness state as SSH-specific metadata; none are generic `targets` columns. A literal IP is immediately known at registration but must not be labeled host-key verified before trusted verification.
- **DNS-based hosts:** distinguish the registered hostname, provisional DNS results and the **actual policy-approved TCP peer IP selected for the SSH connection**. Only report it as verified after the pinned SSH host key is validated, before credentials are sent. Display `IP not yet verified` when unavailable, and clearly mark a previously observed IP as stale when appropriate. No guessed, arbitrary or cached DNS candidate may masquerade as a live authenticated peer.
- **Human identifier:** render `display name — deploy@203.0.113.10:22 — prod-ssh` for IPv4 and `display name — deploy@[2001:db8::10]:22 — prod-ssh` for IPv6; also show hostname when configured. For an as-yet-unverified hostname, show `username@hostname:port — target_id (IP not yet verified)`. Targets with the same IP but different OS username, port or Target ID must remain visibly separate.
- **Operator flows:** the IP-inclusive identifier belongs on authorized SSH add/confirmation, inventory, Target picker, detail, test, connect/reconnect and command/file destination confirmation surfaces, not only diagnostics.
- **Authorized MCP identity:** `targets-list` and `target-context` return bounded SSH-specific, non-secret context: stable `target_id`, display name, normalized IP (configured literal or last verified actual connection IP where known), port, username, optional hostname and IP verification/freshness status. Do not reveal private addresses to unauthorized users or clients. Ordinary list/context/search perform no network probing or DNS lookup.
- **Search and command boundary:** support bounded local, authorization-filtered inventory lookup by normalized IPv4/IPv6, optional IP:port and registered hostname. Return all matching authorized Targets on ambiguous/shared IPs. Commands and SFTP operations still require an **exact authorized `target_id`**; arbitrary caller-supplied IP/hostname never becomes SSH routing authority.

Changed IP, DNS answers, TCP destination or host key must be rechecked under registered endpoint/network egress and pinned host-key policy with explicit verified rebinding where appropriate. For an executed action, displayed effective connection IP must describe the policy-approved, verified connected peer, not a pre-connect DNS candidate. This is required initial SSH acceptance under #123 revision 2 and its dependent #108/#109/#110/#112 contracts.

## Transport and trust

- Use a narrowly scoped SSH adapter (evaluate maintained phpseclib compatible with pinned PHP/Composer) and SFTP adapter; **SSH is not an MCP server**, so the common MCP-over-HTTP adapter used for WordPress and future explicitly supported MCP-native Targets is not applicable to SSH wire framing.
- Remote endpoint identity is the operator-approved host/port and verified host-key binding; do not invent an Agent-style `instance_id`. Store connector-only metadata separately from `targets`. Endpoint and username changes require revalidation/reconnection as appropriate, never silent credential or identity reassignment.
- SSH TCP egress has its own enforceable address/port/DNS/rebinding policy; reuse shared principles, **not HTTPS-only checks**. Default to explicit admin-registered public destinations. Explicitly allow a private/VPN destination only through an operator-approved scoped network policy for that deployment/Target, rechecking resolved/connected addresses; never create a blanket internal-network scanner/SSRF proxy through MCP inputs.
- No automatic credential forwarding to other hosts, no transparent jumps/agent forwarding, no unsafe unknown host-key acceptance, no unbounded ports/redirects.
- Network/handshake/exec/read/write timeouts, finite output bytes, bounded memory, concurrent connections and per-operation duration apply even when commands themselves are unrestricted. If an operation times out or the connection fails after dispatch, the remote command/file mutation **may have occurred**: return `outcome_unknown` and do not auto-retry.
- Keep full command text, SSH secrets, raw output and file data out of default Gateway activity/logs. Audit the authenticated user/client, Target, tool, correlation and outcome with safe bounded metadata; downstream shell activity policies are the remote OS's responsibility.

## Initial command and file semantics

- Each ordinary command runs in its own SSH exec context. Working directory/environment/shell state do **not** persist between tool calls; callers must express context in the command they request. Exit code can be unavailable on transport failure.
- A truncated stdout/stderr preview is explicitly incomplete and **not resumable** unless the operation actually stores output somewhere. Never re-run an arbitrary command just to obtain the rest of its output.
- File reads may support byte ranges with source identity/preconditions where available; files changing between ranges need conflict/fresh-read semantics. Avoid lossy binary-to-text conversion.
- File paths are explicit, validated, bound to the selected authenticated Target and not sourced from hidden arbitrary URL/host arguments. Account/symlink/chroot behavior is determined by the remote server; no false claim that disabling SFTP tools or filtering paths constrains unrestricted shell access.
- Simple SFTP file transfer should be byte-streamed/chunked with a finite cap, not serialized into MCP JSON or loaded whole into PHP memory. Large durable resumable transfers, background SSH jobs, PTY/interactive terminal and file-manager UX are deferred; keep adapter interfaces compatible with future additions.

## Implementation sequencing and release boundary

Depends on #107 (Target identity/access), #108 (explicit registry, not HTTP assumption), #109 (encrypted purpose-aware credentials), #110 (Admin/permissions/public MCP) and #117 (client-neutral authenticated context). **#123 does not depend on #111/Agent #47**, and #111 does not depend on #123. Both may be implemented independently after shared foundations. Program #106 now intends three supported connectors; final #112 evidence includes SSH only after the exact implementation is integrated.

Do not add a required daemon/queue/SSH binary/PHP SSH extension to the ordinary PHP 8.4 and MariaDB/MySQL deployment merely to enable simple SSH. Hosting outbound TCP port reachability and request execution limits are operational prerequisites; describe supported fallback honestly.

## Acceptance: minimal correct deliverable

1. Two successful test logins (password and key, with encrypted-key passphrase when compatible); wrong credentials fail safely.
2. Previously verified host key succeeds; first-use unverified or changed host key fails **before authentication**; controlled rotation/rebind works.
3. Target-specific command execution with arbitrary shell text, including a representative non-interactive permitted `sudo`/root case; get exit code/stdout/stderr/truncation correctly. Do not pretend interactive password prompts work without a PTY.
4. Separate Gateway permission and Target-scope tests reject unauthorized use and preserve default denial for existing non-owner accounts; file-toggle versus unrestricted-command caveat is visible.
5. Public/private approved-target egress boundaries, DNS/port controls, host-key mismatch and cross-Target secret isolation are tested.
6. Output flood, timeout, disconnect, cancellation and repeated-call behavior preserve caps and `outcome_unknown` (no blind retry).
7. SFTP stat/list/ranged read/small write and bounded basic transfer succeed where supported; malformed path, permission denial, changing source, partial upload and binary data are handled without leakage/corruption.
8. The existing WordPress connector behavior, shared-host release packaging and client auth/Target routing remain intact; the canceled Agent connector is not a live acceptance dependency.
9. Normalized IPv4/IPv6 (including bracket formatting), verified effective DNS-connected IP versus unknown/stale IP states, and `name + username@IP:port + target_id` appear in authorized Admin/picker/MCP selection and connection context. Local IP search handles shared-IP/multi-account ambiguity, unauthorized access returns no endpoint metadata, and command/SFTP cannot route by arbitrary IP.

## Not in first delivery

No generic remote terminal/PTY, always-on SSH session, durable command job manager, arbitrary relay/proxy, automatic SSH server provisioning, auto-accept host key, passwordless privilege escalation policy, universal resumable GB transfer, or mandatory queue/worker. Add these only through a concrete reviewed requirement, not as hidden acceptance for the initial connector.
