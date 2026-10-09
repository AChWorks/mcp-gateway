# Direct SSH Target Connector

Status: **Owner-accepted target-state design**, implementation pending [Issue #123](https://github.com/AChWorks/mcp-gateway/issues/123).
Parent: [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106).
See also [Target foundation](./TARGET-CONNECTOR-FOUNDATION.md), [remote I/O contract](./REMOTE-IO-CONTRACT.md).

## Product boundary

`ssh_direct` is a **separate, built-in Target connector** for explicitly registered Linux/Unix SSH servers **without requiring AI Server Agent installation**. It supports username/password and username/private-key (+ optional passphrase) authentication. The user selects the remote OS account; the server's account permissions determine actual command privileges, including `sudo` and root when that account is legitimately configured for them.

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

## Transport and trust

- Use a narrowly scoped SSH adapter (evaluate maintained phpseclib compatible with pinned PHP/Composer) and SFTP adapter; **SSH is not an MCP server**, so the common MCP-over-HTTP adapter used for WP AI Bridge and Agent is not applicable to SSH wire framing.
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
8. Both existing WordPress and Agent connector behavior, shared-host release packaging and client auth/target routing remain intact.

## Not in first delivery

No generic remote terminal/PTY, always-on SSH session, durable command job manager, arbitrary relay/proxy, automatic SSH server provisioning, auto-accept host key, passwordless privilege escalation policy, universal resumable GB transfer, or mandatory queue/worker. Add these only through a concrete reviewed requirement, not as hidden acceptance for the initial connector.
