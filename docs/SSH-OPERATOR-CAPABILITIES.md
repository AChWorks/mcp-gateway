# v3 SSH operator capabilities (source candidate)

**Scope:** v3 source implementation under [Issue #328](https://github.com/AChWorks/mcp-gateway/issues/328). Source contracts and CI alone are **not proof** of a published Release, installed Gateway, authorized remote Target mutation or real fleet acceptance. The already-merged shared Target Batch engine is under [#330](https://github.com/AChWorks/mcp-gateway/issues/330); this package adds no SSH Batch coordinator.

## Trust, resource and permission model

Five independent MCP Tools below use the existing SSH Command/SFTP runtimes, original Target identity, scope and current User/Client grants, Pause, pinned host key and Direct/Reverse/Relay selection. Access checks happen before credential load and remote connection; runtimes recheck the current grants and Target binding at effect boundaries. Existing Owner Operational Settings control command byte/timeout/output and SFTP read/write limits. There is no new per-host agent, generic remote proxy, privileged CLI fallback or transport.

The MCP readOnlyHint describes intent and is **not** an OS read-only sandbox. An authorized SSH command grant retains the power of the real remote OS account, including its configured sudo policy.

| Tool | Existing permission | Evidence and outcome |
| --- | --- | --- |
| **ssh-system-inspect** | ssh.command.run | Requested system, uptime, load, CPU, memory, storage, processes, service and listener facts; per-section source, units, exit and observed/failed/unsupported/partial outcome. No inference of health from missing systemd or data |
| **ssh-network-diagnose** | ssh.command.run | Exact destination DNS, route, TCP, verified TLS, HTTP, ICMP latency or protocol-aware UDP DNS response. Source, exit, response and incomplete evidence. Transmitting UDP alone cannot count as success; HTTP numeric status alone is not app health |
| **ssh-logs-query** | ssh.command.run for journald, ssh.file.read for SFTP file mode | Bounded journald JSON with source cursor/time/level/unit and UTC times when present; or base64 SFTP offset/length and size/mtime without fabricated per-line timestamps. Distinguishes truncated, unsupported and unknown; failed/unsupported journald queries are Tool failures, never successful Activity |
| **ssh-file-patch** | ssh.file.read for preview; **both** ssh.file.read and ssh.file.write for apply | One unique localized UTF-8 substitution of a regular file. Preview supplies original/proposed SHA-256 and bounded diff with no effect. Apply demands the previewed exact SHA, current file preflight, private SFTP staging and original owner/group/all POSIX mode bits preservation with independent remote readback. This is **not** atomic compare-and-swap against arbitrary remote writers |
| **ssh-change-verify** | ssh.command.run | Independently checks file SHA-256, systemd service state, TCP open or HTTP status at an explicit optional health path (default /) against an explicit expected value; optional before observation, actual source/exit and passed/failed/unsupported/unknown outcome. Reload exit zero alone is not service health |

**Effective limits:** Inline patch content must fit the already configurable SFTP write window (default 16 KiB, adjustable to 512 KiB). A patch snapshot uses **one bounded SFTP session** instead of repeated reconnects for each read window, with a separate session for post-write verification. Larger files use existing authorized whole-file or script paths rather than inventing an unbounded inline contract. If remote SFTP cannot preserve original owner/group or **any** original permission bit (including setuid/setgid/sticky), patch refuses publication rather than silently changing metadata. Known prepublication patch refusals expose their specific error and separate private-stage cleanup evidence without changing established generic ssh-file-write semantics; a lost publication response remains outcome_unknown. Previewed diffs are true line-oriented unified changes, and explicitly truncated UTF-8 output must not be mistaken for a complete patch. Symlinks, binary files and ambiguous match sets are rejected. Size/mtime and SHA-256 checks detect typical drift, but a remote concurrent writer can still win the race; observe an uncertain effect rather than replaying it.

## Service-specific *composed* configuration changes

The accepted **ssh-config-apply** is a composed operator workflow, **not** a universal new MCP Tool. For an individually authorized service and its real validation/reload/health contracts:

1. Determine the exact file, OS account, service and baseline. Inspect as needed and preview the patch without changes. Review its diff and baseline SHA-256.
2. Stage the *proposed* service configuration as an explicitly authorized isolated scratch file using existing SFTP file write, when the service-specific validator supports it. Run that actual validator on the proposed bytes **before apply**. Failure/unknown must stop; leave the active configuration and service unchanged.
3. After successful prevalidation and separate authorization for the remote change, apply the exact SHA-preconditioned patch. If drift, permissions, ownership, publication or verification are unknown, stop and inspect/reconcile rather than blindly retrying. Revalidate the published configuration, if the validator supports it, before issuing reload.
4. Only after proven validation, run an authorized service-specific reload/restart through the existing SSH command or Job operation. Command acceptance is **not** proof of health.
5. Independently check resulting file digest and service state **plus actual behavior/health**. Track file_modified, syntax_validated, reload_accepted and service_healthy separately. If a check fails, stop and use explicit service recovery; never blindly fan out.

Some real validators accept only the active path and cannot prevalidate staged bytes. In that exceptional case, the operator must explicitly accept and record the partial file-change risk, validate immediately after patch and **never reload after failed validation**. This is an operator-composed boundary, not a universal atomic config transaction or rollback.

A CI-only loopback OpenSSH/isolated test HTTP service exercises success and validator-failure paths; its Python service-specific --check is a disposable fixture, not a general-purpose config evaluator. Real host changes are not authorized by this documentation.

## Remaining gates and source truth

Source unit tests and fake-denied transport tests cannot substitute for CI's disposable **real** OpenSSH tests. Exact-head GitHub CI, MariaDB/Batch regressions, independent review, Owner merge approval and any separately authorized installed-host acceptance are distinct gates.

The shared SSH command Batch consumer, WordPress read-only proof, status/list/cancel and durable Target Batch core from PR #331 remain unchanged. Long-idle ChatGPT OAuth, full authorized Human/Web Batch UX, representative real multi-Target acceptance, v3-to-v3 updater, official release and Production cutover have separate Owner gates tracked through #330; recheck current Issue/Release state before acting. [#327](https://github.com/AChWorks/mcp-gateway/issues/327) and [#200 Phase C](https://github.com/AChWorks/mcp-gateway/issues/200) remain Owner-parked.
