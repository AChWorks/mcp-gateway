# Remote Results and File Transfer Contract

Status: Accepted current result/transfer design for public **v2.2.1**. WordPress routing, SSH commands and SFTP are shipped; the OAuth-authenticated SSH whole-file HTTP path and Target capability discovery (PR #166) are **shipped but disabled by default**. Independent PHP/Python clients verified binary upload/download and SHA256 on disposable installed Gateway, not on this owner's production host. Native ChatGPT attachments/model file return, WordPress/Agent raw binary modes and universal MCP-host support are not yet verified. AI Server Agent #111 is paused.
Current work owners: [client-neutral transfer #147](https://github.com/AChWorks/mcp-gateway/issues/147), [cross-layer effective capacity and Bridge compatibility #154](https://github.com/AChWorks/mcp-gateway/issues/154), [Owner Admin operational tuning #153](https://github.com/AChWorks/mcp-gateway/issues/153), [mixed acceptance/release #112](https://github.com/AChWorks/mcp-gateway/issues/112).
Provenance: [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106), [completed bounded-response #122](https://github.com/AChWorks/mcp-gateway/issues/122), [SSH backend #123](https://github.com/AChWorks/mcp-gateway/issues/123).
Related: [Target foundation](./TARGET-CONNECTOR-FOUNDATION.md), [Direct SSH connector](./DIRECT-SSH-CONNECTOR.md).

**#147 delivered SSH mode, remaining client handoff separate:** The opt-in raw HTTPS-to-SFTP whole-file contract, permission-filtered `target-context` mode descriptor and independent external-client byte verification are documented once in [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md). They are shipped in public v2.1.2 and v2.2.1, but any real-host enablement and proxy/client capacity acceptance are separate decisions. Finite SSH-mode limits are not a global cap on WordPress, paused Agent #111 or future connector-specific modes.

## Purpose and scope

A registered Target may expose small JSON, large structured collections, command output, binary files, or long-running work. These have different continuation and integrity properties. The Gateway must offer **one coherent set of semantics**, not one unlimited transport/body size. Design semantics here are common; implementation belongs to the actual connector and operation. Do not claim every backend can page or resume.

Keep the ordinary case cheap: a small result is one authenticated request and one bounded response. A registered but idle Target requires no worker, polling, permanent stream, or storage allocation.

## Workload-aware resource envelopes: one policy, different limits

**Owner-accepted direction (2026-10-11):** A small metadata call, a slow analytical tool, a large ZIP/media transfer and a future long-running stream must not share one arbitrary WordPress-sized body ceiling or one request timeout. Select bounded resources by **real capability, operation, data representation and deployment**, with efficient small-workload behavior. A future one-hour AI Server Agent stream is a design example, **not a shipped capability**; [Agent #111](https://github.com/AChWorks/mcp-gateway/issues/111) remains Owner-paused.

| Budget axis | Unit and scope | Why it must remain separate |
| --- | --- | --- |
| Input / decoded reply | Bytes **per authenticated HTTP/MCP call**, including serialization/compression expansion | A 64 KiB ordinary WordPress decoded reply is not a global file size ceiling |
| In-memory buffer/window | Bytes **per stream block** plus queued-buffer limit | A 16 KiB inline SFTP call or 64 KiB internal block does not define a whole ZIP/PDF limit |
| Aggregate object / transfer | Bytes **for the completed source/destination object**, independently metered | Multiple blocks may form a larger object only when a real supported data plane assembles and verifies them |
| Connect, DNS, TLS/SSH handshake | Seconds **per connection phase/attempt** | Failure before dispatch is distinct from an uncertain dispatched mutation |
| First byte, idle/progress and request | Seconds **per wait, stream inactivity, or individual HTTP request** | A progressing stream and a stalled stream must not be treated alike |
| Overall logical operation/task | Finite duration **across multiple requests or a supported continuous session** | A 60-minute logical job need not monopolize a 60-minute PHP/HTTP worker |
| Host, principal and Target capacity | Concurrent jobs, memory, disk, bandwidth, admission queue | Admission must account for active work, not allocate full permitted quotas for idle Targets |
| Continuation and durability | Source-backed cursor, byte range, checkpoint or retained job ID | A returned file path/MCP resource link is not an automatic replay-safe resume or a model-readable file |

**Policy selection — shared, predictable, no name-based special cases:**

1. Authenticate the exact Gateway user/client profile and selected registered Target; enforce existing Target/operation grants and downstream authority. Discover only actually implemented/negotiated client, protocol, Target and host capabilities. New downstream tool names are **not** a hard-coded ban or a reason to deploy another Gateway version.
2. Classify the authorized *operation family and execution risk*: ordinary metadata/structured read; confirmed read-only; unknown/mutating; native file/ranged stream; command with bounded preview; genuinely stateful task. Unclassified work does not self-promote to a higher read-only quota. Do not let untrusted Target metadata bypass security or set arbitrary quotas.
3. For **each identical unit and scope separately**, resolve the stricter applicable bound from immutable resource/egress safeguards, observed provider/client/proxy/host limits, reviewed Owner Admin defaults and relevant scoped overrides, and this request's finite budget. Reject or negotiate a real compatible fallback when peer constraints conflict. **Never take the minimum of incomparable values:** per-chunk bytes, total file bytes, idle seconds and total task seconds are not interchangeable.
4. Choose the cheapest supported delivery mode: one inline result, source-owned page/range, bounded streaming with backpressure, authenticated direct/handoff transfer or genuine retained job+polling. Avoid multi-megabyte Base64 in JSON, pretending a cursor exists, duplicate per-client/Target transfer engines or an always-on connection per registered Target.
5. Meter actual decoded/encoded bytes, elapsed work, memory/concurrent admissions and temp disk as data flows; a high configured maximum **never means up-front allocation**. On rejection, report safe effective limit, units, limiting layer and supported next step; no raw secret/data logs. A timed-out or disconnected dispatched mutation may have 'outcome_unknown' and must **not** be blindly retried.

**Configuration ownership:** [#153](https://github.com/AChWorks/mcp-gateway/issues/153) owns the *single typed, persisted, Owner-only operational settings subsystem* and evidence-based selection of defaults/limits (source config fallback, effective value, audit, reset). Begin with global baseline plus connector/workload profiles and add an optional exact Target override **only after a real use case** proves it necessary. Prefer extending the same registry/validation, not a separate table, UI or rate policy for every tool and provider. Group real knobs by connections, response/transfer, execution lifetime, concurrency and health; make them finite and mutually consistent. Actual immutable memory/network/auth bounds, OAuth provider rotation/recovery windows, Target permissions and host limitations remain non-overridable. [#154](https://github.com/AChWorks/mcp-gateway/issues/154) owns versioned **effective client↔Gateway↔Target limit/capability evidence**, not a second settings service; [#147](https://github.com/AChWorks/mcp-gateway/issues/147) owns the actual common byte-transfer/integrity/data-plane implementation.

**Implementation boundary:** Existing source defaults 64 KiB ordinary WordPress decoded response, 256 KiB confirmed read-only and 8 MiB absolute decoded HTTP guard are *one adapter's current values*, not an all-Target budget. [PR #156](https://github.com/AChWorks/mcp-gateway/pull/156) is merged as the **first source-integrated two-key Owner override**, a shipped first tuning slice, not proof that every effective client/host capacity limit has been measured. Shipped SFTP 16 KiB inline windows and 64 KiB internal blocks remain separate from the *optional* whole-file SSH HTTP edge, whose configured maximum is per **synchronous SSH operation** (see [whole-file contract](WHOLE-FILE-EXCHANGE.md)). Do not infer native MCP-host download/model ingestion, hour-scale work, resumability, WordPress or Agent modes from the verified external-client SSH transfer. Publication and installed-host support must be evidenced separately.

### Future long-lived streaming and hour-scale logical work

A one-hour *logical* operation does **not** imply every ChatGPT client, MCP transport, CDN/proxy or shared-PHP host can hold one HTTP socket or PHP worker open for an hour. Keep **connection establishment**, **time to first result**, **idle/progress timeout**, **single-request lifetime**, **overall logical-session lifetime** and **authentication validity** independent. Use a truly supported streaming transport with bounded backpressure/heartbeat/cancellation only if both peers and the deployed host support it. Progress/heartbeats may reset a separately configured *idle* timer; they **do not extend** the approved maximum logical lifetime. Persisted job state and owner-safe polling/resume should be added only for a real consumer that needs them; do not fabricate continuation by re-executing a mutation.

At each new authorized chunk/poll/connection, re-check principal/client/Target binding, exact operation and source identity. Never assume a one-hour operation can reuse an expired one-hour bearer; renew credentials **only** under actual provider-approved rules, without DB-held network I/O or changes to the one-shot uncertain-rotation fence. Disconnects, expired leases, downstream process restart, slow consumers, dropped heartbeats, revocation, quota pressure and cancellation require truthful partial/unknown outcomes, bounded cleanup and scoped progress evidence. A future long-lived Agent adapter may use retained state, short polling or a streaming lease based on **real** infrastructure evidence after the Owner explicitly unpauses [#111](https://github.com/AChWorks/mcp-gateway/issues/111). No speculative Agent-specific code or required daemon is authorized today.

**Acceptance tests when each mode is actually implemented:** small requests under large allowed quotas (no max-size preallocation), response Base64/JSON overhead and decoded limit boundaries, read-only vs mutating outcome, finite chunk vs aggregate ZIP/PDF/media integrity/digest, concurrency and memory/disk cost, first-byte delay, slow-but-progressing and stalled streams, cancellation, revoked credentials, proxy resets and recoverability. Exercise a simulated hour-scale timeline plus a disposable real host soak when the relevant long-duration mode exists; short unit tests alone cannot assert one-hour production connectivity. Record observed p50/p95 latency, bytes, timeouts, memory/CPU and admission pressure and use this evidence to revise defaults. An unsupported host/client feature must be called **unsupported**, not **forbidden** or **completed**.

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
- The ordinary WordPress decoded-body response default of 65,536 bytes is an **existing runtime fact**, not a universal Target limit. Bounded-response #122 is complete; future measured configuration belongs to #153 and Bridge/client compatibility to #154. Do not globally increase or silently remove the safety guard.
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

**Direct SSH (#123):** bounded command previews (#145), stat/list and up-to-16-KiB inline reads/writes (#146), and private internal SFTP streams (#148) remain connector-native. **PR #166 now composes these streams into an optional authenticated whole-file SSH HTTPS ingress/egress mode**, separately discovered via `target-context`. PHP SDK and independent Python clients really saved and verified the bytes. Native chat/model file ingestion, stronger remote snapshots, durable SSH resume, broad host acceptance and release remain unproven/pending (#147/#112). No always-on PTY/job/transfer service required.

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
| Shipped SSH/SFTP inline calls and streams | **16 KiB decoded per inline read/write**; **64 KiB internal SFTP blocks** | The public `ssh-file-write` call does not append a larger file via repeated calls; these are not *aggregate* file caps |
| Optional SSH whole-file HTTPS edge (**shipped v2.1.2+; off by default**) | Default 8 MiB/30 sec; audited Owner-configurable maximum **64 MiB/40 sec for this synchronous SSH mode only** | Actual whole-object upload/download bytes and SHA-256 passed on two independent HTTPS/MCP clients in the disposable installed test. It requires a client capable of sending and receiving authenticated raw HTTPS binary bodies; disabled by default. Proxy/host effective limits may be stricter |
| ChatGPT host-native file attachment / model-readable return, WordPress whole-file binary or future Agent through Gateway | **UNVERIFIED / NOT IMPLEMENTED as applicable** | A URL, MCP resource, host-local path or successful independent HTTP download is **not** proof that a model can consume that file; no SSH budget or ability name whitelist transfers to other Target types |

For any size-sensitive operation, record **source bytes, Base64 bytes, serialized Bridge JSON, downstream HTTP decoded bytes, final Gateway MCP response bytes, real client/host attachment mode, effective configured/immutable limits, origin/version and the limiting layer**. Test small text, UTF-8 expansion, binary ZIP/media, at-boundary oversize, concurrent requests, interrupted reads/writes and exact byte/hash identity. Use representative latency and peak memory/disk evidence to choose non-security default budgets (#153); higher permitted maxima do not imply higher resource usage for small requests. A Bridge-side admin setting is not a Gateway setting, and no Gateway setting may disable credential/Target/client authorization, network pinning, one-shot refresh safety or memory/transport hard guards.

**Ownership / follow-through:** #154 owns the evidence-backed *versioned* numeric/capability matrix and honest compatibility runbook; #153 owns one validated Owner Admin configuration subsystem; #147 owns the **shared** authenticated byte transfer mechanism across actual supported client and Target adapters. Do not create per-file-extension/per-client duplicate security pipelines or turn passive ZIP receipt into WordPress extension installation. Release/installation claims require actual artifact/host checks, not design prose.

## Proportional work and independent ceilings

A **maximum permitted size does not imply a preallocated buffer**. For a request of 10 KiB under a validated 256 KiB maximum, process only the actual 10 KiB plus necessary framing, encoding, authentication and transport overhead. Avoid unnecessary staging, copying or SSH reconnects for small data. Stream unknown-length content with bounded reusable buffers and enforce an independently bounded total size as bytes arrive. A hard payload quota is a safety guard, **not** the mechanism by which the product becomes performant.

Keep **per-inline-call**, **per-stream buffer/window**, **whole-transfer bytes**, **deadline/worker occupancy**, **concurrency** and **temporary disk** distinct. An inline SFTP 16 KiB guard is not an end-user file-transfer ceiling. Use actual client/Target capabilities and measured round trips, connection count, p50/p95 latency, peak memory/CPU, temp disk and error behavior to select appropriate inline ceilings, chunk/window sizes and streaming versus private authenticated handoff. Comparison workloads should cover small files under a much higher permitted maximum and representative medium/larger binary content. Do not demand a new queue/object store/daemon to solve a small-file efficiency problem.

The *same* Gateway transfer authorization/integrity/quotas/outcome policy must serve verified clients and supported WP/SSH Target adapters without one data-transfer engine per extension, tool or application. Public file-return links and opaque references do not prove the model can consume file bytes; verify client ingress and actual model-readable versus user-downloadable egress independently. For security/execution gates and acceptance use #147 and #112.
