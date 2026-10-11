# Remote Results and File Transfer Contract

Status: Accepted Target/data transport contract. Bounded SSH/SFTP MCP operations (#146) and internal SFTP streams (#148) are integrated into **source**, not evidence of a particular [published release](https://github.com/AChWorks/mcp-gateway/releases) or installed Gateway. Authenticated client-neutral file handoff (#147), binary delivery into/out of the real MCP host and durable continuation remain unimplemented/unverified; do not advertise them as working.
Current work owners: [client-neutral transfer #147](https://github.com/AChWorks/mcp-gateway/issues/147), [cross-layer effective capacity and Bridge compatibility #154](https://github.com/AChWorks/mcp-gateway/issues/154), [Owner Admin operational tuning #153](https://github.com/AChWorks/mcp-gateway/issues/153), [mixed acceptance/release #112](https://github.com/AChWorks/mcp-gateway/issues/112).
Provenance: [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106), [completed bounded-response #122](https://github.com/AChWorks/mcp-gateway/issues/122), [SSH backend #123](https://github.com/AChWorks/mcp-gateway/issues/123).
Related: [Target foundation](./TARGET-CONNECTOR-FOUNDATION.md), [Direct SSH connector](./DIRECT-SSH-CONNECTOR.md).

## Purpose and scope

A registered Target may expose small JSON, large structured collections, command output, binary files, or long-running work. These have different continuation and integrity properties. The Gateway must offer **one coherent set of semantics**, not one unlimited transport/body size. Design semantics here are common; implementation belongs to the actual connector and operation. Do not claim every backend can page or resume.

Keep the ordinary case cheap: a small result is one authenticated request and one bounded response. A registered but idle Target requires no worker, polling, permanent stream, or storage allocation.

## Control plane versus data plane

- **Control:** MCP returns bounded structured data, previews, status, errors, pagination/range metadata, and approved opaque result/transfer handles when a real backing source exists.
- **Data:** binary and large files should use authenticated SFTP, bounded/streamed HTTP endpoints, or a backend-approved direct Target-to-destination transfer as appropriate. Never stuff multi-megabyte files into MCP JSON/base64 by default.
- MCP resource links and asynchronous task handles are *optional negotiated integrations*, not a guarantee that a given MCP client can upload/download binary content. Keep authenticated Admin HTTP workflows usable without a client-specific binary feature.
- Do not build a generic Gateway object store, generic workflow engine, background worker, or proxy tunnel for this contract. Add persistent result storage only when a proven consumer needs continuation of **non-repeatable** output.

## Result classes and correct continuation

| Class | Normal response | Large response / next step |
| --- | --- | --- |
| Small JSON / text | Bounded inline payload | Typed oversize error or available connector-owned pagination; do not fabricate a cursor |
| Structured collection or nested tree | Filtered projection / bounded page | Stable cursor/selector/subtree read *implemented by the source*; never cut JSON mid-document and call it valid |
| One-off command stdout/stderr | Bounded preview, separate stdout/stderr, exit status and timeout | Explicit `truncated` / `complete`; remainder is **not retrievable** unless actually spooled or exposed by a persistent job |
| Ranged immutable/stable file | Bounded `offset`/`length` read with identity/precondition | Further independently authorized ranges; ensure unchanged source (size/mtime/hash or stronger token, where supported) |
| File upload/download | Metadata/control via MCP | Authenticated SFTP or streamed HTTP body with bounded concurrency, disk/memory and lifetime |
| Long-running job | Job ID/status/output only when connector supports it | Poll and read bounded output chunks; no re-execution just to retrieve prior output |

A continuation token is opaque, short-lived where appropriate, scoped to authenticated Gateway user, client profile when relevant, Target, operation and backing-result identity; it is not an authorization grant on its own. If the source cannot guarantee stability, report the limitation and require an explicit refresh rather than silently splicing inconsistent chunks.

## Result and failure semantics

The **semantic contract** is stable even when public tool-specific JSON field names evolve before implementation:

- Success distinguishes `completed`, `in_progress` (only with a real backing job), `partial` (only with explicit completeness semantics), and failed/unknown outcome.
- For command results, report `stdout` and `stderr` separately where supported; preserve `exit_code` (nullable when unavailable), encoding, per-stream byte limits, `truncated`, and whether further output is actually retained. A truncated preview is **not** a successful complete capture.
- For structured data, return a syntactically complete bounded page or a typed error; never turn a chopped JSON tree into a plausible complete result.
- An oversize downstream read reports stable `response_too_large` and safe diagnostics (configured effective limit, known minimum/observed count where safe, phase such as transfer/decoded body). Do **not** return/log the rejected body, credentials, command secrets, or raw internals.
- Connector-specific error metadata may remain server-side. Gateway authorization/Target non-enumeration and client-profile isolation apply to error details and handles too.
- A command, file write or other mutation interrupted after dispatch may have executed. Report `outcome_unknown`; never auto-retry merely because the HTTP/SSH connection broke or the payload was truncated.
- Logging defaults to identity/correlation, type, outcome, duration and bounded counts, not raw command text, stdout/stderr or file contents.

Do not conflate **transport response-size bounds** with **application pagination**. A larger ceiling cannot fix an all-or-nothing API. In particular, targeted Gutenberg discovery/read belongs to [WP AI Bridge #100](https://github.com/AChWorks/wp-ai-bridge/issues/100); the Gateway retains its finite transport envelope.

## Bounds, performance and implementation boundaries

- Retain hard upper ceilings for per-operation request bytes, *decoded* response bytes, connect/total time, concurrency, in-memory buffers, preview size and temporary storage. Where needed, allow **finite validated operator tuning** per connector/tool under an absolute cap; do not raise every WordPress response limit to accommodate Agent/SSH.
- The current WP AI Bridge default `BRIDGE_REMOTE_MAX_RESPONSE_BYTES=65536` is an existing runtime fact, **not** the permanent universal Target limit. Review it with representative payloads under #122; do not silently remove or globally increase it.
- Preserve compressed/decoded expansion and unknown Content-Length protection, cancellation semantics, SSRF/SSH egress controls and destination identity checking.
- Stream actual file data in bounded chunks with backpressure; never read the entire file/job log into PHP memory to return a small range. Validate expected length and checksum when provided.
- Client-upload/download entrypoints must re-check Gateway session/token authorization and exact Target permission on each request; short-lived download references never become public unscoped URLs. Temp paths must live outside `public/`, have quotas/expiry/cleanup and cannot be accessed across users/Targets.
- Uploads use explicit destination intent, bounded size, path/overwrite rules and (where possible) temporary-file plus atomic rename; fail safely on partial write and do not imply rollback if the downstream operation is not atomic.
- Avoid silent data transformations: distinguish UTF-8 text from opaque bytes, specify binary-safe encoding only for small bounded inline bytes, and preserve file integrity through streaming paths.
- File transport is connector-dependent: initial `ssh_direct` can use SFTP; AI Server Agent retains its own ranged file and job contracts; WP AI Bridge uses application-level bounded APIs. **Do not force SSH into MCP-over-HTTP transport.**
- On normal request/response paths, avoid synchronous multi-gigabyte transit through PHP shared hosting. A future larger transfer may require chunked authenticated HTTP, external storage/direct transfer, or an explicit durable transfer session, evaluated against hosting limits.

## Delivery sequence and ownership

**Completed bounded-response foundation (#122):** finite decoded response protection, typed oversize failure, effective-limit diagnostics and focused tests are integrated. This is NOT a public file data plane or proof that increasing one Bridge message budget allows a larger end-to-end MCP response. Further current source/installed capacity compatibility belongs #154, and actual client-to-Target/Target-to-client file handoff belongs #147.

**Foundation (#108 / #109 / #110):** factor shared downstream MCP bounds and error propagation where truly common; keep connector-owned payload/transport and stable Target/user authorization. Do not introduce a generic large-object framework before the third real connector demonstrates a need.

**Direct SSH (#123):** bounded command previews merged in #145, and bounded stat/list, up-to-16-KiB binary-safe inline range reads and small writes merged in #146. Explicit atomic last-writer-wins replacement is available with optional best-effort size/mtime preflight (never CAS); internal bounded stream primitives merged in #148. **Neither makes real client-side file ingress or model-consumable file egress work.** Those authenticated client handoffs, strong source-version guarantees and interrupted transfer recovery remain unproven/pending (#147/#112). No always-on PTY/job/transfer service required.

**Final acceptance (#112):** validate small-path latency, oversize/encoded/unknown-length handling, no cross-Target/credential leaks, interrupted-write unknown outcomes, representative large file and mixed-connector limits, and supported shared-PHP packaging. Add only tests for capabilities actually shipped.

**Future, demand-driven:** resumable transfer with durable ID/offset/checksum, spooled command output, durable SSH jobs, PTY/interactive stdin, richer MCP Tasks integration, object-storage offload. They are architectural extension points, **not release blockers** and must not be advertised until implemented and tested.

## Effective limits belong to the whole path

**The current inventory, measured values and provider versions live in [#154](https://github.com/AChWorks/mcp-gateway/issues/154), not in copied release/head snapshots in this design contract.** A per-call message limit, an internal stream block size, a WordPress per-document quota, a MIME restriction, a PHP host upload cap, a Gateway decoded HTTP body guard and the total bytes of a completed file are **different units, enforcing different invariants**. The effective behavior depends on the authenticated caller, operation classification, Target, installed provider revision and actual receiving MCP host; it cannot be inferred by reading the largest number in a component.

Illustrative **source-only compatibility checkpoint**: Gateway main at 481bb8e215c651a2a1e290de3e15064848043ecd and [WP Bridge DRAFT #145 HEAD 061e162](https://github.com/AChWorks/wp-ai-bridge/tree/061e162d65c130b4f5892b86035b294e5f3f84f1), inspected 2026-10-11. This is an example, **not** a published or installed capability claim; verify live revisions before use:

| Boundary | Source default / status | How to interpret |
| --- | --- | --- |
| Gateway ordinary/possibly mutating downstream HTTP response | **64 KiB decoded JSON-RPC HTTP body**; bounded via Gateway configuration | Not a universal text/file size; an unknown mutation whose response exceeded the budget cannot be blindly repeated |
| Gateway confirmed read-only downstream HTTP response | **256 KiB decoded HTTP body**; separate configuration, subject to **8 MiB absolute decoded-body guard** | Does not grant read-only classification to unknown/untrusted operations or bypass client-side MCP reply framing |
| [WP AI Bridge **DRAFT** PR #145](https://github.com/AChWorks/wp-ai-bridge/pull/145) | Proposed **128 KiB encoded JSON response** and **128 KiB UTF-8 read-window** defaults; WordPress Admin finite settings, **not merged/released here** | An output valid under its draft Bridge limit can still be **too large for Gateway's 64 KiB ordinary route** once encoded. A 128 KiB window is not a maximum WordPress document length or a complete inbound text writer |
| Source-integrated SSH/SFTP | **16 KiB decoded inline range read / whole write**; **64 KiB internal stream blocks** | The public ssh-file-write operation does **not** assemble a larger file from repeated chunks; internal blocks are not yet a client-facing ingress/egress protocol. A ZIP/PDF/video is not thereby capped at 16 KiB in the *future* real streamed data plane |
| Real ChatGPT/other client ↔ Gateway ↔ Target file transit | **End-to-end capability and aggregate maximum unverified** until [#147](https://github.com/AChWorks/mcp-gateway/issues/147) acceptance | A server path, MCP resource URL, link, Base64 window or user download is not automatically bytes the model can actually consume |

For any size-sensitive operation, record **source bytes, Base64 bytes, serialized Bridge JSON, downstream HTTP decoded bytes, final Gateway MCP response bytes, real client/host attachment mode, effective configured/immutable limits, origin/version and the limiting layer**. Test small text, UTF-8 expansion, binary ZIP/media, at-boundary oversize, concurrent requests, interrupted reads/writes and exact byte/hash identity. Use representative latency and peak memory/disk evidence to choose non-security default budgets (#153); higher permitted maxima do not imply higher resource usage for small requests. A Bridge-side admin setting is not a Gateway setting, and no Gateway setting may disable credential/Target/client authorization, network pinning, one-shot refresh safety or memory/transport hard guards.

**Ownership / follow-through:** #154 owns the evidence-backed *versioned* numeric/capability matrix and honest compatibility runbook; #153 owns one validated Owner Admin configuration subsystem; #147 owns the **shared** authenticated byte transfer mechanism across actual supported client and Target adapters. Do not create per-file-extension/per-client duplicate security pipelines or turn passive ZIP receipt into WordPress extension installation. Release/installation claims require actual artifact/host checks, not design prose.

## Proportional work and independent ceilings

A **maximum permitted size does not imply a preallocated buffer**. For a request of 10 KiB under a validated 256 KiB maximum, process only the actual 10 KiB plus necessary framing, encoding, authentication and transport overhead. Avoid unnecessary staging, copying or SSH reconnects for small data. Stream unknown-length content with bounded reusable buffers and enforce an independently bounded total size as bytes arrive. A hard payload quota is a safety guard, **not** the mechanism by which the product becomes performant.

Keep **per-inline-call**, **per-stream buffer/window**, **whole-transfer bytes**, **deadline/worker occupancy**, **concurrency** and **temporary disk** distinct. An inline SFTP 16 KiB guard is not an end-user file-transfer ceiling. Use actual client/Target capabilities and measured round trips, connection count, p50/p95 latency, peak memory/CPU, temp disk and error behavior to select appropriate inline ceilings, chunk/window sizes and streaming versus private authenticated handoff. Comparison workloads should cover small files under a much higher permitted maximum and representative medium/larger binary content. Do not demand a new queue/object store/daemon to solve a small-file efficiency problem.

The *same* Gateway transfer authorization/integrity/quotas/outcome policy must serve verified clients and supported WP/SSH Target adapters without one data-transfer engine per extension, tool or application. Public file-return links and opaque references do not prove the model can consume file bytes; verify client ingress and actual model-readable versus user-downloadable egress independently. For security/execution gates and acceptance use #147 and #112.
