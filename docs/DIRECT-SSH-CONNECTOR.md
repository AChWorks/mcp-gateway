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

### Updating registered endpoint or credentials

The Admin separates low-risk display-name editing from sensitive connector reconfiguration. Changes to hostname, port, OS user, pinned server key or authentication material require actual Owner authorization, password confirmation and optimistic revision checks. Secrets are never returned in form fields or flashed after invalid input. A retained unchanged secret is re-encrypted/rebound only when the connector's supported rules make that safe; changing credential method requires a new secret.

A substantive edit invalidates old verified peer/login evidence. An old in-flight verification cannot approve the new binding. **Verify SSH host and login** again before accepting execution; neither user/Target grants nor previous OS account rights automatically transfer to an arbitrary replacement host. Disconnecting locally removes Gateway's stored credential; it does **not** revoke the OS account or terminate existing SSH sessions.

## 2. Exact Gateway permissions and OS authority

The three existing Gateway capabilities are:
- `ssh.command.run`: arbitrary non-interactive shell commands under the configured OS account;
- `ssh.file.read`: bounded SFTP metadata, directory and file-read operations;
- `ssh.file.write`: bounded SFTP file writes and authorized upload modes.

Non-Owner capability grants require deliberate appropriate Owner review/confirmation, the applicable Target scope and role ceiling, and must not appear automatically through ordinary group assignments. Denies and Target Pause continue to apply. **Granting arbitrary shell execution can read or alter remote files even when SFTP tools are denied.** Gateway does not sandbox shell text, strip `sudo`, ban root usernames or falsely promise per-command business restrictions. OS permissions, configured `sudo -n` and remote policy determine actual powers; interactive password/TTY prompts are outside non-interactive exec.

Admin UI and MCP tool descriptions may warn about high privilege, but neither a descriptive annotation nor a presentation switch is an authorization mechanism.

## 3. Synchronous command and SFTP Tool semantics

**`ssh-command-run`** launches one non-interactive remote exec for the exact authorized Target; no working-directory, environment or shell session persists between calls. Its UTF-8 command-input maximum, timeout and separately capped `stdout`/`stderr` are finite and reported by current Tool schema/Owner settings. An exit code may be unavailable; truncation is explicit and **not** a resumable command-output stream. A timeout, disconnect or response loss after possible command dispatch is **`outcome_unknown`**—never automatically rerun an effectful command merely to obtain more output.

The MCP SFTP Tool family `ssh-file-stat`, `ssh-file-list`, `ssh-file-read` and `ssh-file-write` uses the same trust/identity checks with distinct read/write grants. A directory listing is bounded; file reads return binary-safe Base64 with an explicit finite byte window and EOF/source metadata; small writes have their own per-request window. **These are per-call limits, not an overall supported-file-size guarantee.** Source size/mtime checks may detect many changes but are **not atomic CAS** or a cryptographic snapshot.

For creation or replacement, require validated explicit paths and suitable private staging. Create-only must not overwrite an existing destination; explicit overwrite uses actual supported SFTP atomic publication semantics with truthful last-writer-wins/precondition limitations. Verify private remote staging permissions and complete bytes before publication where supported. If the real SFTP subsystem is refused, fail rather than silently falling back to executing shell commands. Path ownership, symlinks, account chroot and filesystem permissions remain remote-host rules.

The internal `SshFileRuntime` stream methods can exchange bytes with **already authorized local/remote streams** using bounded reusable blocks, verified private staging and length/digest checks. Their existence alone does not give the AI client a binary upload/download transport. No arbitrary source URL, stream wrapper, generic remote file server or unsupported resume cursor is implied.

## 4. Detached SSH Jobs

The authenticated MCP Job family has four separate methods:

| Tool | Meaning |
| --- | --- |
| `ssh-job-start` | Submit a finite UTF-8 script with a client-generated UUID `request_id` and selected runtime; receive a durable `job_id` and state |
| `ssh-job-status` | Inspect the same Job under its original authenticated user/client/Target binding and reconcile supported remote terminal evidence |
| `ssh-job-output` | Read bounded `stdout` or `stderr` Base64 windows by offset without starting the command again |
| `ssh-job-cancel` | Request stop of the exact remote unit; confirm **canceled** only after independently verifying no live process, otherwise report **cancel_requested** |

Job admission requires all three Gateway SSH capabilities: command + SFTP read + SFTP write, an authenticated original Target binding and verified remote SSH identity. Subsequent status, output and cancellation requests recheck original principal/client/Target binding and their applicable current rights. Job script/output are kept in a restrictive **remote** private location, not in the Gateway Activity or database. Gateway retains non-secret durable ID/digest/original-host snapshots needed to distinguish requests and support recovery.

**Job script-input staging:** The Owner can independently configure `ssh_job_max_script_kib` (default 16 KiB; permitted 16–64 KiB). Authenticated `ssh-job-start` discovery reports the effective script schema limit; the coordinator also checks actual UTF-8 byte length. Scripts up to 16 KiB retain the existing atomic single-window SFTP path. Larger approved scripts use the same verified bounded streaming SFTP engine into the original private Job directory, with `0600` files, byte/hash readback and exclusive publication under the original Target binding. An uncertain staging outcome cannot advance to wrapper creation or systemd dispatch. Changing the Owner policy does not erase old Job records or make a rejected oversized duplicate safe to replay: reconcile by the original `job_id`. The separate 16 KiB SFTP write/read and Job output windows are unchanged.

**Remote host prerequisites:** working `systemd-run` and a persistently available, operator-approved systemd user manager with `linger`, or supported root manager for a deliberately configured root account. An unsupported manager fails before staging. Scripts/wrappers are staged via verified SFTP in a restricted `0700` remote directory with `0600` files; a transient systemd unit performs the bounded work and records a durable exit marker. Job execution can outlive an HTTP/PHP request without running a Gateway agent.

**Replay and retention rules:**
- Duplicate **same `request_id` + same bound arguments** returns the original Job while its journal is retained; different arguments conflict and do not launch a second script.
- The journal is durably recorded before remote side effects, and a possibly sent launch may be **`launch_unknown`**. A disconnected request, expired admission lease or lost reply **never** licenses a new launch of that Job.
- Active concurrent admission, selected runtime, pre-dispatch recovery window, post-dispatch reconciliation grace, terminal retention and Job script-input budget are **independent finite policies**. Read actual effective values from Owner Operations and MCP schema. A higher Job script input does **not** increase the ordinary SFTP single-window or Job output-window size.
- The original remote host, port, OS user and pinned-key digest are snapshotted immutably for later reconciliation; if original identity cannot be proven after account/Target rotation/deletion, mark it **unknown**, never infer a replacement Target.
- A provably abandoned **pre-dispatch** preparing attempt can fail without remote I/O. Genuine remotely uncertain Jobs cannot be automatically pruned merely because a runtime/lease or terminal-retention threshold passed.
- Cancellation is not remote rollback. Cleanup of original spool/unit and terminal status must be verified before any operator-led retirement.

**Diagnosing read/admission failures:** An authenticated SSH MCP caller can use the
`diagnostic_reference` returned by an actionable `ssh-job-*` or `ssh-file-*`
failure with the read-only `operation-diagnostics-read` tool, subject to
current `activity.view` and Target/client scope. Retained/idempotent
`launch_unknown` or `job_unsupported` summaries may not carry a new
reference; instead read bounded recent errors for the authorized `target_id`.
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
