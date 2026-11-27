# Direct SSH Target connector

**Purpose:** define how Gateway connects to a deliberately enrolled SSH host, authorizes its operations, transfers files and manages retained Jobs. For shared Target/permission rules use the [Target connector contract](TARGET-CONNECTOR-FOUNDATION.md); for payload and result semantics use [remote I/O](REMOTE-IO-CONTRACT.md). Actual installed-host capabilities and budgets depend on its verified release and effective Owner settings.

## 1. Enrollment, identity and trust

`ssh_direct` is a built-in **agentless** connector. Each Target is identified for routing by its stable Gateway `target_id`, not by a caller-supplied hostname, IP or label. The connector stores registered host/IP, TCP port, OS username, authentication method and an **independently trusted pinned SSH server public host key** in connector-specific records. Login secrets (password or private key and optional passphrase) are encrypted, purpose-bound and write-only in the Admin.

**Every admitted SSH connection must follow this sequence:**

1. Authenticate the actual Gateway principal/client and authorize the requested capability on the exact Target. Check the current operation-pause and admission restrictions.
2. Resolve the registered endpoint within the approved bounded SSH TCP egress policy. Validate candidate addresses and the **actual numeric TCP peer**; do not fall back to a different unapproved host or turn submitted IPs into arbitrary destination authority.
3. Cryptographically verify the server's actual host key against the **out-of-band pinned key before sending password/private-key credentials**. Unsupported/weak algorithms, mismatch or changed binding fail closed.
4. Authenticate as the configured remote OS account, then recheck sensitive Target/authorization state near effectful remote operations. Do not retain database row locks across DNS, TCP, key exchange, login or SFTP network I/O.

A configured IP can be displayed before connection but is not thereby host-key verified. Display authorized endpoint context with `username@IP:port`, optionally hostname, immutable Target ID, and **verified / unknown / stale** actual-peer status; format IPv6 in brackets. Two Targets with the same IP but different users or ports remain different choices. Inventory and search use bounded **stored evidence**, not network probes, and never reveal unauthorized host details.

Private/VPN network eligibility is an explicit reviewed egress-policy question, **not** a permission to disable public-address, host-key or SSRF boundaries. SSH host-key identity is independent of WordPress HTTPS/TLS identity and must not be passed through the latter's HTTP-only adapter.

### Reverse SSH for inbound-blocked Targets

**Two supported enrollment paths:** The existing **manual operator-managed**
route uses the explicit `SSH_REVERSE_APPROVED_ROUTES` allowlist and host
operator provisioning documented below. The separately approved, optional
[Managed Reverse SSH](REVERSE-SSH-MANAGED.md) path instead uses an isolated
one-time Gateway host bootstrap, permission-authorized durable enrollment,
per-Target loopback listener and one-use Target installer. It **does not**
require per-Target `.env` allowlist edits or manual key/port allocation.
Both paths preserve the same end-to-end Target SSH host-key pin, login,
Target permissions and retained Job revision fencing; neither is a public
proxy or automatic Direct fallback.

A Target may choose **Direct (default)** or **Reverse SSH**. A Direct-mode
SSH Target may additionally select an Owner-registered
[Connection Relay](CONNECTION-RELAYS.md) as its outbound OpenSSH/SOCKS5
intermediary. The real Target host key and credentials are still verified,
and Relay failure never silently becomes Direct. This does not create a new
connector or change the Reverse SSH model. Reverse SSH is still the
built-in, agentless `ssh_direct` connector: a restricted OpenSSH **client on the
Target** opens one **remote** forward to a loopback-only listener on NL. Gateway
only dials **127.0.0.1 on the approved NL port**. It never picks arbitrary local
URLs, DNS addresses, private ranges or a caller-supplied proxy destination.

**In the manual allowlist path, two independent approvals** are mandatory:
1. A NL deployment operator places a strict JSON allowlist entry for the stable
   `target_id`, one unique high port and an agreed tunnel identity in
   `SSH_REVERSE_APPROVED_ROUTES`, and provisions a dedicated restricted NL
   SSH tunnel account and key. The string identity is an **operator mapping and
   audit label**, not a cryptographic attestation of a listening process.
2. A user with targets.create or scoped targets.configure selects Reverse during enrollment or configuration,
   enters the exact allowlisted port and identity, confirms the pinned **real
   Target** host key and re-enters their own Gateway password. The preapproved host route remains mandatory regardless of role.

On every verification, command and SFTP operation the Gateway rechecks the
operator mapping before the connection and at the post-login operation/verification
authority fence; SFTP staged writes recheck again at each write boundary. A missing or changed mapping fails
closed; an unavailable listener does **not** trigger a direct retry. The TCP
socket peer is verified as **127.0.0.1:approved-port**, then the original Target
server's **pinned public SSH host key is cryptographically verified before
transmitting login credentials**. A compromised or misbound local listener
cannot authenticate as another host without the matching pinned host private
key. The control-channel NL host key is separately pinned by the remote
OpenSSH client and is **not** the same as the end Target host key.

A Reverse listener is **not** the Iran Target's observed network address.
Gateway leaves `observed_peer_ip` empty, records when the end-to-end pinned
login was verified, and displays the original registered Target endpoint
separately from the NL loopback route. No listener health is implied by a
previous successful verification.

Sensitive route changes require scoped configuration permission, current-actor password confirmation,
transaction and optimistic-revision gates. A path-only change clears current route verification but preserves the existing verified login and encrypted credentials. Synchronous SSH,
SFTP, whole-file exchange and retained Jobs continue to use the same
permission, pin, recheck and audit code. Retained Job launches preserve their exact original transport and endpoint/trust revisions; a Reverse->Direct->Reverse round trip never revives old dispatch authority. Fresh authorized observation of a retained artifact is separate from dispatch. Existing valid login envelopes are migrated once to a path-independent digest, with exact Target, endpoint, account and pinned host key checks. A genuine endpoint/trust identity change advances its own revision and re-seals credentials. Replacing login material for the same endpoint does not change the endpoint binding, but advances its semantic credential grant. New in-flight command, SFTP, multi-phase Job launch and Verify work compare the exact peer, route, grant and credential material; changing only the path never decrypts or re-seals the login. A same-grant reseal preserves a deferred Batch approval, but an explicit replacement requires a new approval. Existing Job identity evidence remains unchanged; new Jobs additionally record original peer/account evidence, exact launch admission and durable launch observations. One-time migrations preserve only provably exact never-dispatched queued Batch bindings, without rewriting stale or already-dispatched journal evidence.

The PHP application itself never obtains root access, changes SSHD,
opens firewall rules or starts privileged systemd services. The **managed**
path has a separately approved, narrow, root-executed host installer with
owned service/account boundaries; it is not a general privileged web agent.
The **manual** operator-managed OpenSSH/systemd procedure, bounded
permissions, diagnostics, validation and rollback are in the
[Reverse SSH operator runbook](REVERSE-SSH-OPERATOR.md).
Without separately approved host-level operations, an installed Gateway
can only register the route and fail closed until the external forward exists.
A CI/OpenSSH fixture is not a production acceptance test.

### Updating registered endpoint or credentials

The Admin separates low-risk display-name editing from sensitive connector reconfiguration. Changes to hostname, port, OS user, pinned server key or authentication material require scoped targets.configure authorization, current-actor password confirmation and optimistic revision checks. Secrets are never returned in form fields or flashed after invalid input. A retained unchanged secret is re-encrypted/rebound only when the connector's supported rules make that safe; changing credential method, verified host key or OS username requires a new secret.

A substantive edit invalidates old verified peer/login evidence. An old in-flight verification cannot approve the new binding. **Verify SSH host and login** again before accepting execution; neither user/Target grants nor previous OS account rights automatically transfer to an arbitrary replacement host. Disconnecting locally removes Gateway's stored credential; it does **not** revoke the OS account or terminate existing SSH sessions.

## 2. Exact Gateway permissions and OS authority

Before presenting stored credentials, the transport checks current execution/control authority and the exact admitted Target/endpoint/trust/route/material or verification attempt after host-key exchange. New command and SFTP staging/publication effects also recheck authority. Existing cleanup and uncertain-result handling remain separate from a grant to start new work. These boundaries apply to native direct, Relay and Reverse paths; they do not imply a distributed atomic login or publication.

The three existing Gateway capabilities are:
- `ssh.command.run`: arbitrary non-interactive shell commands under the configured OS account;
- `ssh.file.read`: bounded SFTP metadata, directory and file-read operations;
- `ssh.file.write`: bounded SFTP file writes and authorized upload modes.

Non-Owner capability grants require deliberate appropriate Owner review/confirmation, the applicable Target scope and role ceiling, and must not appear automatically through ordinary group assignments. Denies and Target Pause continue to apply. **Granting arbitrary shell execution can read or alter remote files even when SFTP tools are denied.** Gateway does not sandbox shell text, strip `sudo`, ban root usernames or falsely promise per-command business restrictions. OS permissions, configured `sudo -n` and remote policy determine actual powers; interactive password/TTY prompts are outside non-interactive exec.

Admin UI and MCP tool descriptions may warn about high privilege, but neither a descriptive annotation nor a presentation switch is an authorization mechanism.

## 3. Synchronous command and SFTP Tool semantics

**`ssh-command-run`** launches one non-interactive remote exec for the exact authorized Target; no working-directory, environment or shell session persists between calls. Its UTF-8 command-input maximum, timeout and separately capped `stdout`/`stderr` are finite and reported by current Tool schema/Owner settings. The Owner may independently raise the input and captured stdout/stderr ceilings to **512 KiB each**, and select up to **600 seconds** for the exec phase; defaults remain 8 KiB input, 16 KiB stdout, 8 KiB stderr and 15 seconds maximum. Complete streams are drained packet by packet even after the requested preview is full; excess bytes are discarded (never buffered indefinitely or persisted). The result distinguishes captured bytes from observed total bytes, with per-stream truncation flags, original binary/UTF-8 encoding and the actual exit status only when proven. A missing exit proof, timeout, disconnect or response loss after possible dispatch is **`outcome_unknown`**—never automatically rerun an effectful command merely to obtain more output.

**`ssh-script-run`** is the explicit synchronous alternative when a script must not be passed as native SSH exec argv. Supply UTF-8 `script`, the exact absolute `interpreter` executable path (for example `/bin/sh` or `/usr/bin/python3`), `target_id` and optional `timeout_seconds`. The interpreter receives the staged script path as its argument; there is no interpreter guessing, shebang selection, appended interpreter flags, command splitting or implicit Job conversion. The configured command input and output byte ceilings apply unchanged; the selected timeout is one shared monotonic deadline across admission, preparation, transfer, execution and best-effort cleanup. This mode requires both `ssh.command.run` and `ssh.file.write` (internal readback is part of verified writing, not a grant to read arbitrary files). It needs a compatible non-interactive POSIX shell, Linux-style `stat` and `sha256sum`, a writable private `/var/tmp`, an SFTP subsystem sharing that filesystem with exec, the existing verified SFTP publication support, and the requested interpreter. It does not require systemd. Native commands retain their original behavior and do not require SFTP.

A fresh private directory and witness bind preparation, verified SFTP upload and launch to the same admitted Target, credentials, route and filesystem artifact. Exact byte count and SHA-256 are checked after upload and again in the exec namespace before invoking the interpreter; no script content enters exec argv. The result includes `script_bytes`, `script_stage`, `script_staging_verified`, `script_launch_attempted` and `temporary_cleanup_confirmed`. Launch-attempt evidence is not proof the interpreter started: the returned native exit belongs to the guarded launcher (including an integrity refusal or interpreter failure). A failure before launch is distinct from uncertain execution but staging may already have created files. After proven completion, or a verified owned staging directory with no launch attempt, cleanup checks the witness and removes only the known files and directory, under current authority and remaining time. Unconfirmed cleanup retains the exact private locator and a diagnostic reference; unknown launch is never automatically retried or cleaned as though the interpreter had stopped. No durable Job or output history is created. A configured 512 KiB byte limit is not a promise of native argv capacity or of all client/host paths; the staged mode is qualified separately. For deadline-bound SSH/SFTP connections, the original peer-verified socket is used through a deadline-aware stream from identification and key exchange through authentication and channel I/O. TCP/SOCKS and actual socket waits consume the same remaining monotonic budget; recompute the library timeout after current-authority checks. The library's initial identification select uses whole-second rounding; this is not a claim of hard process cancellation or of bounding arbitrary local CPU work. Known control-command failures retain the failed preparation/cleanup step, actual native exit and relevant owned-path utility evidence in correlated Activity; cleanup diagnostics are separate from the confirmed launch result. Arbitrary control output, script bytes and private witness values are not retained.

**Timeout capability gate:** The 600-second *setting* is not an installed-host guarantee. SSH transport, PHP worker lifetime (plus connection margin), Target admission lease, HTTPS proxy/CDN and the MCP client all need independently verified effective deadlines. The command lease scales with the selected timeout (minimum existing 90s) to protect per-Target serialization. A separate monotonic wall-clock deadline is checked during each output callback (including after bounded capture), and the remaining budget caps the next phpseclib socket wait. Continuous output cannot restart the command budget. A deadline crossed after possible dispatch is **`outcome_unknown`**, never proof that the remote process exited; the per-Target lease also includes a separate 90-second transport/cleanup margin. A PHP worker already configured with a finite shorter deadline rejects the operation **before dispatch** (`timeout_unsupported`). An unverified proxy/client hop can still close a request after remote execution began; the outcome then remains uncertain. Never extend unrelated WordPress or OAuth request lifetimes for SSH. Prefer retained SSH Jobs when this chain cannot support synchronous work.

The MCP SFTP Tool family `ssh-file-stat`, `ssh-file-list`, `ssh-file-read` and `ssh-file-write` uses the same trust/identity checks with distinct read/write grants. Each SFTP directory page is bounded by count (100) and an independent aggregate UTF-8 filename-byte ceiling; a signed, user/Target/SSH-binding/path/limit-scoped cursor resumes after the preceding page. The implementation uses standard SFTP READDIR and closes each handle after the request; phpseclib does not expose a native seekable continuation API, so later pages must rescan skipped entries and very large listings have increasing total scan cost. The protocol provides no stable snapshot: concurrent directory mutations may shift entries, so restart from page one when the directory changes. No shell fallback or hidden unlimited filename array is permitted; file reads return binary-safe Base64 with an explicit finite byte window and EOF/source metadata; writes have a separate decoded-byte window. The Owner can raise each of the three ceilings independently from its 16 KiB default to at most 512 KiB. **These are per-call limits, not an overall supported-file-size guarantee.** Source size/mtime checks may detect many changes but are **not atomic CAS** or a cryptographic snapshot.

For creation or replacement, require validated explicit paths and suitable private staging. Create-only must not overwrite an existing destination; explicit overwrite uses actual supported SFTP atomic publication semantics with truthful last-writer-wins/precondition limitations. Verify private remote staging permissions and complete bytes before publication where supported. If the real SFTP subsystem is refused, fail rather than silently falling back to executing shell commands. Path ownership, symlinks, account chroot and filesystem permissions remain remote-host rules.

The internal `SshFileRuntime` stream methods can exchange bytes with **already authorized local/remote streams** using bounded reusable blocks, verified private staging and length/digest checks. Their existence alone does not give the AI client a binary upload/download transport. No arbitrary source URL, stream wrapper, generic remote file server or unsupported resume cursor is implied.

### v3 non-production operator diagnostics and safe file patching

The additional source-only SSH system/network/log inspection, localized patch/independent verify, and service-specific composed config workflow are documented in [v3 SSH operator capabilities](SSH-OPERATOR-CAPABILITIES.md). They are **not an installed v2 feature**. The existing shared Batch engine stays unchanged; the accepted config apply is a composition, not a new universal Tool.

## 4. Detached SSH Jobs

The authenticated MCP Job family has five separate methods:

| Tool | Meaning |
| --- | --- |
| `ssh-job-start` | Submit a finite UTF-8 script with a client-generated UUID `request_id` and selected runtime; receive a durable `job_id` and state |
| `ssh-jobs-list` | Discover retained Jobs for this exact user, OAuth client/profile, and authorized Target; optionally filter by status and paginate with a scoped signed cursor; **database-only**, with no remote execution or per-Job polling |
| `ssh-job-status` | Read retained metadata for the original user/client and immutable Target; reconcile supported remote evidence using current authority |
| `ssh-job-output` | Read bounded `stdout` or `stderr` Base64 windows by offset without starting the command again |
| `ssh-job-cancel` | Cancel a provably unlaunched intent locally, or stop the exact remote unit and independently verify no live process; otherwise retain **cancel_requested** |

A new conversation can use `ssh-jobs-list` with the same authorized Gateway user, OAuth client/profile and `target_id` to recover a retained `job_id` without rerunning anything. Listings include only bounded status, timestamps, expiration and stored terminal metadata (no scripts or output). They exclude expired terminal records; uncertain nonterminal records remain discoverable until reconciled. Discovery requires current command permission and Target scope for the original immutable Target record and original user/client/profile. Pause, disconnection, route or credential changes do not hide that history. A deleted/recreated Target or different principal never inherits it. Cursor scope is independent of route; a cursor issued before the history-scope update may require a new listing. Read-only discovery never uses SSH.

Job admission requires all three Gateway SSH capabilities: command + SFTP read + SFTP write, an authenticated original Target binding and verified remote SSH identity. Subsequent status, output and cancellation requests recheck the original principal/client/Target record and applicable current rights. Every Job-specific SFTP output, overflow/exit marker and identity-witness read composes the current command grant with the native SFTP read grant at login and each protected observation boundary, including on a freshly verified changed binding. Ordinary SFTP uses its own rights; status can still obtain command-only systemd evidence if optional file-read authority is absent. A fresh remote follow-up uses the current verified route and credential dispatch fingerprint, never the old execution approval. If the original composite binding changed, the new pinned login must prove the original host key and account and the exact private 0600 Job witness in its 0700 spool, on the same authenticated operation/session. Route, endpoint alias, port or login-material changes alone do not preclude proof; a different key/account, missing witness or different Target record cannot authorize access. Pre-marker historical Jobs keep their exact original-binding recovery path; on a changed binding their metadata remains available but remote continuation cannot be inferred. A remote failure preserves recorded state and reports current failure separately. Job script/output are kept in a restrictive **remote** private location, not in the Gateway Activity or database. Gateway retains non-secret durable ID/digest/original-host snapshots needed to distinguish requests and support recovery.

**Job script-input staging:** The Owner can independently configure `ssh_job_max_script_kib` (default 16 KiB; permitted 16–512 KiB). Authenticated `ssh-job-start` discovery reports the effective script schema limit; the coordinator also checks actual UTF-8 byte length. Scripts up to 16 KiB retain the existing atomic single-window SFTP path. Larger approved scripts use the same verified bounded streaming SFTP engine into the original private Job directory, with `0600` files, byte/hash readback and exclusive publication under the original Target binding. An uncertain staging outcome cannot advance to wrapper creation or systemd dispatch. Changing the Owner policy does not erase old Job records or make a rejected oversized duplicate safe to replay: reconcile by the original `job_id`. The separate SFTP read, write and Job output per-call windows remain independent Owner controls (16 KiB defaults, at most 512 KiB). The internal 16 KiB staging blocks do not become 512 KiB allocations, and the retained output budget is unchanged.

**Job output vs ordinary files:** The remote private `stdout` and `stderr` captures each retain at most **1 MiB**, with excess output drained so a verbose child does not fail due to a full log. `ssh-job-output` uses a distinct Owner-selected 16–512 KiB read window per request (default 16 KiB); it does **not** increase retained bytes. At terminal EOF, `truncated=true` requires a confirmed private overflow marker; `false` requires a below-cap spool **and** durable proof that both capture readers finished (the wrapper's durable `exit-code` file, recorded as `terminal_reason=script_exit` with a non-125 exit status); `null` means capture completeness is unverified, including canceled/terminated units without reader proof, exit 125 (also used for collector failure), and full-size legacy logs without an overflow marker. A stored-file EOF or terminal systemd state alone never proves capture completeness. These caps apply **only to captured output**, not package installation, archives, application files or other writes by the detached script. There is no unit-wide `LimitFSIZE` constraint.

**Remote host prerequisites:** working `systemd-run` and a persistently available, operator-approved systemd user manager with `linger`, or supported root manager for a deliberately configured root account. Only a completed explicit negative capability result becomes `unsupported/job_unsupported`. A denied or failed SSH connection, authentication, expired/revoked admission, nonzero probe failure or unconfirmed probe response becomes a retained `failed/pre_dispatch_failed` intent with its actual native error and diagnostic reference. Neither outcome stages files or admits detached execution; exact request recovery never probes again. A historical unsupported record without explicit negative evidence must not be interpreted as a confirmed capability rejection. Scripts/wrappers are staged via verified SFTP in a restricted `0700` remote directory with `0600` files; a transient systemd unit performs the bounded work and records a durable exit marker. Job execution can outlive an HTTP/PHP request without running a Gateway agent.

**Replay and retention rules:**
- Duplicate **same `request_id` + same bound arguments** returns the original Job while its journal is retained and the original caller retains command scope, without requiring a current route or renewed file-write grant; different arguments conflict. The advertised Tool input schema still governs submitted calls; use list/status if an earlier request no longer fits the current schema.
- The journal is durably recorded before remote side effects. Probe, staging and final systemd dispatch recheck the exact active attempt and native authority. `launch_admitted=false` proves the detached script was not admitted (staging files may exist); `true` means systemd exec was admitted, not acknowledged; legacy `null` means no durable admission evidence. A possibly sent launch may remain **`launch_unknown`**. Local expiry/cancel serializes against final admission, and late launch observations never overwrite an authoritative terminal/cancel state. A disconnected request, expired admission lease or lost reply **never** licenses a new launch of that Job.
- Active concurrent admission, selected runtime, pre-dispatch recovery window, post-dispatch reconciliation grace, terminal retention and Job script-input budget are **independent finite policies**. Read actual effective values from Owner Operations and MCP schema. A higher Job script input does **not** automatically increase ordinary SFTP read/write windows or the Job output read window.
- The original remote host, port, OS user and pinned-key digest are snapshotted immutably for later reconciliation; if original identity cannot be proven after account/Target rotation/deletion, mark it **unknown**, never infer a replacement Target.
- A provably abandoned **pre-dispatch** preparing attempt can fail without remote I/O. Genuine remotely uncertain Jobs cannot be automatically pruned merely because a runtime/lease or terminal-retention threshold passed.
- Cancellation is not remote rollback. Cleanup of original spool/unit and terminal status must be verified before any operator-led retirement.

**Diagnosing read/admission failures:** An authenticated SSH MCP caller can use the
`diagnostic_reference` returned by an actionable `ssh-job-*` or `ssh-file-*`
failure with the read-only `operation-diagnostics-read` tool, subject to
current `activity.view` and Target/client scope. Retained/idempotent
`launch_unknown`, pre-dispatch failure or `job_unsupported` summaries reuse stored launch evidence
references where available; legacy rows may require bounded recent errors for the authorized `target_id`.
Never invent a new reference for an old response. The Admin Activity view uses
the same bounded, selectively redacted Activity record. A pre-dispatch
`connection_busy`/`rate_limited` refusal is recorded there without an
additional per-attempt PHP log warning; internal or remotely uncertain failures
retain operator warning evidence. Native SFTP error codes/messages are kept
**only when received**; an unknown provider cause stays unknown. No remote Job
script, stdout/stderr content, command body or file bytes are written to
diagnostic logs. An unavailable reference does not justify replaying a Job
launch, cancel or write whose outcome is uncertain.

### Operator recovery for uncertain Jobs

Use the **installed Gateway's trusted local Artisan CLI** with the ordinary unprivileged site PHP user and approved operating procedures:

```bash
php artisan gateway:ssh-jobs-reconcile inspect
php artisan gateway:ssh-jobs-reconcile inspect YOUR_EXACT_26_CHARACTER_JOB_ID
```

The hourly `gateway:ssh-jobs-prune` scheduler command now performs two bounded sweeps: terminal-retention cleanup and read-only stale-Job reconciliation. Persisted keyset cursors advance past older blocked or deleted identities, wrap after reaching the end, and report scan/eligible/processed/cleaned/unresolved reasons with a diagnostic ID. A terminal Job's remote spool is removed only with current authenticated original artifact identity (same binding or fresh route with exact witness). For an explicitly never-admitted launch, wait for the staging lease to expire; otherwise require an independently observed original **loaded** stopped systemd unit with zero main/control PIDs (a `systemctl show` success with `LoadState=not-found` **alone** never authorizes deletion; a collected unit requires either a previously verified cancellation or exact matching exit-code marker rechecked in the private spool during cleanup), followed by private directory ownership/mode checks. Missing evidence or an unavailable original user/Target leaves the journal intact. For forensic recovery run `gateway:ssh-jobs-reconcile inspect`; neither the hourly task nor operator inspection replays scripts. Production cleanup is still subject to approved deployment and remote-identity evidence.

Before explicitly retiring an uncertain record, independently confirm that the **original** remote unit has stopped and the **original** remote spool has been removed, including after a Target/user deletion or credential/host change. The saved host-key digest is a non-secret reconciliation clue, **not a substitute for new out-of-band identity verification**. An expired lease or successful stop request alone does not prove cleanup.

Only after that verified work may an authorized local deployment operator attest the original cleanup:

```bash
php artisan gateway:ssh-jobs-reconcile retire YOUR_EXACT_26_CHARACTER_JOB_ID \
  --confirm=YOUR_EXACT_26_CHARACTER_JOB_ID \
  --binding=ORIGINAL_64_CHARACTER_BINDING_SHA256 \
  --reason="Verified original systemd unit stopped and original spool removed" \
  --attest-remote-cleaned
```

Inspect `php artisan gateway:ssh-jobs-reconcile --help` and the current journal first. This local command makes **no SSH call** and does not restart work; its `retired` state means **operator-attested cleanup**, not observed remote success, and cannot be applied to a still-admitted nonterminal Job. Guarded schema rollback may remain blocked while unreconciled Job journal rows exist. Never delete those rows/tables to bypass the no-replay fence.

## 5. Whole-file client exchange

A separately authorized same-origin HTTPS **raw binary** mode composes the existing SSH streams, but is enabled only when the actual feature flag, authenticated client/user, Target, direction and resource budgets permit it. For a supported upload/download, preserve private staging, exact destination identity, bounded total bytes, readback/byte count/hash evidence and safe create-only/explicit-overwrite semantics.

This is **not** an MCP text/base64 Tool call, anonymous browser endpoint, general URL fetcher, automatic WordPress media or plugin installation path, or proof of native ChatGPT model file-parameter support. A standalone external client may use a compatible mode even when the AI host cannot. The protocol, admission and interoperable client verification are in [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md); host configuration and rollout safety in [DEPLOYMENT.md](DEPLOYMENT.md).

**Operator rule:** current supported behavior is determined by installed source and verified effective settings, not a historical version label, green isolated test or successfully constructed remote path.
