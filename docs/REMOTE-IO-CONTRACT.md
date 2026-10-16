# Remote results, resource budgets and file exchange — technical contract

**Role:** one shared specification for result completeness, bounded resource use, cross-hop failures and trustworthy file delivery across the **actual supported** Gateway client/Target connector families. Canonical product intent is [MASTER-SPEC.md](MASTER-SPEC.md), current architecture is [ARCHITECTURE.md](ARCHITECTURE.md); implementation-specific SSH wire behavior belongs to [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md) and [DIRECT-SSH-CONNECTOR.md](DIRECT-SSH-CONNECTOR.md). This document is **not** a release checklist, inventory of current host limits or proof of client-native file attachment support.

Measured effective envelopes and compatibility gaps belong to [#154](https://github.com/AChWorks/mcp-gateway/issues/154); client↔Target *actual bytes* and ChatGPT-host file handoff belong to [#147](https://github.com/AChWorks/mcp-gateway/issues/147); safe cross-hop diagnostics to [#199](https://github.com/AChWorks/mcp-gateway/issues/199). Those owners are separate; no duplicate new transport or diagnostic store is warranted.

## 1. Shared operation plane is not a universal wire transport

An authenticated **Admin** action and an authenticated **AI/MCP** action should reach common application authorization, exact Target/capability selection, dispatch and outcome rules. Admin must not be forced to call its own public `/mcp` endpoint, and an MCP Tool must not be the sole owner of business logic required by Admin. **This is future acceptance, not a claim generic Admin WordPress Ability execution or group publishing ships today** ([#200](https://github.com/AChWorks/mcp-gateway/issues/200)).

The shared application controls **permission, quota/admission, identity binding, integrity, outcome and cleanup semantics**. A connector/client adapter controls wire-specific JSON, HTTP, OAuth, SSH/SFTP, native provider pagination or approved file modes. A connected Target may have capabilities or limits different from every other connector; the Gateway must not silently inherit one connector's synchronous request/window ceiling as the total allowable payload for another legitimate operation.

**Control plane:** small structured result, bounded previews, state/metadata, pagination and trustworthy references where they exist. **Data plane:** real file bytes through an explicitly authorized bounded stream/range/HTTP/SFTP or provider-native direct Target-to-storage handoff, according to client and Target support. A Gateway-hosted object store, arbitrary proxy, generic workflow engine or permanent daemon is not justified merely to move files. Prefer avoiding unnecessary PHP-host transit for large backups/media/export payloads when a trusted Target-native destination route is feasible.

## 2. Typed resource envelope: distinct units and lifetimes

Do not conflate the following budgets or substitute one single “maximum message size” everywhere.

| Resource | Effective unit / boundary | Required behavior |
| --- | --- | --- |
| Ordinary MCP/JSON input | authenticated request bytes, schema/decoded arguments | finite pre-dispatch validation; JSON expansion and overhead accounted for |
| Outbound provider response | **decoded** HTTP response bytes and optionally encoded/wire bytes | enforce actual delivered content, preserve complete or explicit oversize outcome |
| MCP result representation | structured content plus text/Base64 **wire framing** bytes | measure duplication/serialization; downstream advertised payload is not the client-host limit |
| Range or stream buffer | bytes per read/write or transport frame | small reusable bounded blocks; 16 KiB SFTP inline window is **not** 16 KiB max whole-file |
| Complete transfer | total bytes, verified source/destination/temporary storage | a separate finite whole-object budget, available only for a supported direction/mode |
| Host resources | PHP worker RAM/CPU, disk/inodes, outbound connections | admit against actual quotas; large ceiling does not preallocate large buffer |
| Concurrency | active per-principal/Target/workflow jobs/connections | separate from historical Job count and operation lifetime |
| Remote request | connect, first-byte, inactivity and finite per-call deadline | operation-specific, not one WordPress timeout imposed on SSH Jobs |
| Logical job/workflow | duration, durable identity, retention and retry/unknown state | may span multiple ordinary PHP requests without a held worker/socket |
| Client, reverse proxy and Target | provider/host upload limits, accepted encodings, negotiated capabilities | **effective** limit is constrained by all *actual* hops, not the Gateway setting alone |

Default budgets and allowed overrides should be **typed, finite, capability-aware and Owner-adjustable** within real security, deployment and protocol bounds. Keep one coherent existing Owner settings system, not a new module for each Tool/connector. Credential rotation and security/identity fences are **not** operator-tunable performance constants. An input of 10 KiB under a validated 256 KiB allowance should consume roughly its actual bytes and framing, not reserve 256 KiB.

Streaming is not synonymous with unbounded work: use bounded buffers, enforce aggregate totals as bytes arrive, validate source stability/identity where actually supported, and clean up private spool securely. Small workloads should not pay for unnecessary staging, stream copying or new SSH sessions; use the simplest proven source mode.

## 3. Result classes and truthful continuation

| Result class | Normal case | Large/incomplete case |
| --- | --- | --- |
| Small JSON/UTF-8 | one complete bounded reply | typed oversize/unsupported or **source-implemented** pagination; never truncate malformed JSON and claim success |
| Structured collection/tree | projection, filtered subset, bounded page | stable cursor/subtree selection **only if Target implements it**; no invented continuation |
| One-off SSH command | finite separated stdout/stderr preview, nullable exit, truncation flags | truncated output is not retrievable unless actual remote file/result storage exists; never rerun effectful commands to fetch “the rest” |
| Retained SSH Job | stable job identity, actual state, bounded output windows | resume reading stored output by offset only while original binding and retention remain valid; cancellation requests are not proof of stop |
| Binary/document/media | explicitly discovered, permission-filtered file mode, byte count/digest | genuine ranged/streamed/direct data path with consistency and endpoint validation, not a model-facing handle masquerading as bytes |
| Multi-Target action | one record per selected authorized Target and operation | partial success and per-Target unknown outcomes; not an atomic all-or-nothing transaction |

For ranged reads, bind continuation to Target, exact backing object identity and the available source version/hash/size/mtime preconditions. **Size+mtime is best effort, not a cryptographic snapshot.** A changing remote object must yield conflict/fresh-start or an explicitly documented weaker consistency guarantee; do not splice incompatible windows silently. A “cursor” without source support is not a feature.

A public path, signed URL, internal filename, MCP Resource link or opaque file ID **does not prove** that the host delivered usable bytes to the actual human or AI model. Prove ingress and egress independently on the supported client: byte length and cryptographic digest when applicable, filename/MIME where meaningful, verified destination and no data leakage between users/Clients/Targets. A mode proven for a standalone PHP/Python client does not automatically work for the ChatGPT host.

## 4. Transfer admission, integrity and recovery

Preserve exact Gateway user, supported client identity, immutable registered Target, direction, operation permission and provider-bound credentials throughout each authorized transfer. Source/destination endpoint and numeric network/SSH peer identity are connector-owned and revalidated at effectful stages. Per-Target Pause and revocation are rechecked when admitting a **new** remote stage; they do not rewind already committed effects.

For uploads, use private local/remote temporary staging with restrictive permissions, bounded byte admission, source length/hash verification where supported and **atomic publication** when the connector offers it. Create-only must not overwrite a pre-existing destination. An explicit overwrite may require separate Target rights and must preserve real destination semantics; best-effort mtime/size preflight is not atomic CAS. On incomplete transfer, quarantine/clean partial staging where safe; do not report full success from a server-side buffer before remote publication/acknowledged client receipt.

For downloads, verify actual bytes/digest at the receiving endpoint. Unknown client attachment API support, reverse proxy buffering and timeouts, canceled slow consumers or unsupported source continuation can prevent completion; advertise only the supported route and an actionable truthful limitation, not a fake general connector ban.

Always distinguish **per-call SFTP Base64 windows** from optional same-origin, OAuth-authenticated **SSH whole-file binary HTTP routes** and from **WordPress-native Bridge Abilities**. They share identity, limit, integrity and Activity semantics where actually equivalent, **not necessarily a transport implementation or fixed payload ceiling**. Whole-file SSH HTTP remains flag/permission/host dependent. There is currently no proven native ChatGPT chat-file ingress and model-consumable return merely because an independent binary client passed.

## 5. Safe errors, provenance and outcome certainty

Record the **first evidenced** failing stage across only the parts Gateway can observe:

1. **Gateway admission:** authentication/Token, client, Target/Group permission, pause, input schema, rate/byte budget (before dispatch where proven).
2. **Gateway outbound transport:** DNS policy, TCP, TLS/SSH pinned host, connection/timeout/HTTP response ceilings; include structured code, phase and actual comparable limiting units when known.
3. **Downstream MCP/adapter:** initialize/session, `tools/list`, `tools/call`, connector schema/protocol negotiation and safe status.
4. **Provider/Target:** actual authenticated provider-reported classification only if preserved and structurally validated.
5. **Response/receiving host:** Gateway decode/serialize, Base64 and wire overhead, proxy/body bound, real client file handoff if observable.

The WordPress MCP Adapter can strip the original WordPress `WP_Error` code. If Gateway receives only an unstructured `isError=true` and free-form text, **do not invent a provider classification**, scrape localized messages or blame quota/WordPress/policy without evidence. Stable public `error.code` compatibility may coexist with optional, bounded server-side stage/origin/limit context and a reviewed non-enumerating support reference. Ordinary users need a concise safe recovery message, **not** secret hostnames, filesystem paths, internal infrastructure or stack trace; authorized Owner/Admin diagnostics may give safe evidenced detail through the existing Activity/correlation path. Do not add another logging database, per-connector error system or broad sensitive payload capture.

**Outcome certainty is separate from retry eligibility.** Pre-dispatch rejection is different from a completed Target error and from post-dispatch `outcome_unknown`. An HTTP failure, tool `isError=true`, missing response, timeout or canceled connection does not establish a remote write was undone; **never blind-replay** a possibly effectful action. A genuinely idempotent read or provider-enforced exact request ID may have different explicit retry semantics, which must be proven for that operation. Remote cancel requests and expired admission leases do not by themselves prove remote completion.

## 6. Compatibility and acceptance evidence

When validating a connector/feature, test representative small and larger UTF-8/binary bodies, 64/128/256 KiB boundaries where applicable, Base64/text+structured-content duplication, actual client and host/proxy limits, concurrency and slow/canceled consumers, PHP RSS/CPU/temp-disk usage and precise error provenance. Include empty data, changing source, revoked grants, Target Pause, wrong/rotated client/Target identity, partial/unknown effects and SHA/byte parity **only for modes a tested provider really supports**.

Compare p50/p95 latency, number of round trips, allocated memory and reliable throughput with a baseline before adding more workers, caches or connections. Unsupported client mode is **unsupported**, actual authorization denial is **denied**, and uncertain completed effect is **unknown**; neither false success nor misleading security-language obstruction is acceptable.

Source-implemented adapters, a green CI check, published zip, installed host enablement and **real receiving-client/model byte acceptance are separate facts**. Current acceptance gaps are the respective GitHub Issues and actual host evidence, never the version number in this contract.
