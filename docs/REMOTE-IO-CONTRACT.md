# Remote Results and File Transfer Contract

Status: Accepted target-state design; bounded WP and SSH command previews are integrated in main source, not newly released. Four small, bounded SFTP MCP operations are a new candidate; larger authenticated binary HTTP streaming and durable continuation are pending.
Owners: [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106), [bounded-response work #122](https://github.com/AChWorks/mcp-gateway/issues/122).
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

**Now (#122):** reproduce existing WP oversize case, preserve finite decoded-byte limit, add typed safe failure + effective-limit diagnostics/configuration and tests; document connector/tool limit choice and interface with WP #100. Establish the semantics in this document without pretending all future mechanisms ship now.

**Foundation (#108 / #109 / #110):** factor shared downstream MCP bounds and error propagation where truly common; keep connector-owned payload/transport and stable Target/user authorization. Do not introduce a generic large-object framework before the third real connector demonstrates a need.

**Direct SSH (#123):** bounded command previews are merged in #145. The new SFTP candidate handles small inline stat/list, up-to-16-KiB binary-safe base64 ranges and create-only/conditional replace. This is NOT streamed binary HTTP transfer. Large authenticated upload/download, strong source-version guarantees and partial-transfer recovery remain pending. No always-on PTY/job/transfer service required.

**Final acceptance (#112):** validate small-path latency, oversize/encoded/unknown-length handling, no cross-Target/credential leaks, interrupted-write unknown outcomes, representative large file and mixed-connector limits, and supported shared-PHP packaging. Add only tests for capabilities actually shipped.

**Future, demand-driven:** resumable transfer with durable ID/offset/checksum, spooled command output, durable SSH jobs, PTY/interactive stdin, richer MCP Tasks integration, object-storage offload. They are architectural extension points, **not release blockers** and must not be advertised until implemented and tested.
