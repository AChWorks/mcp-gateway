# Remote results, resource budgets and file exchange — technical contract

**Role:** one shared specification for result completeness, bounded resource use, cross-hop failures and trustworthy file delivery across the **actual supported** Gateway client/Target connector families. Canonical product intent is [MASTER-SPEC.md](MASTER-SPEC.md), current architecture is [ARCHITECTURE.md](ARCHITECTURE.md); implementation-specific SSH wire behavior belongs to [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md) and [DIRECT-SSH-CONNECTOR.md](DIRECT-SSH-CONNECTOR.md). This document is **not** a release checklist, inventory of current host limits or proof of client-native file attachment support.

Effective host/client limits must be established from measured behavior, not copied release snapshots. Client↔Target byte delivery, resource admission and cross-hop error provenance are distinct acceptance concerns; no duplicate transport or diagnostic store is warranted.

## 1. Shared operation plane is not a universal wire transport

An authenticated **Admin** action and an authenticated **AI/MCP** action should reach common application authorization, exact Target/capability selection, dispatch and outcome rules. Admin must not be forced to call its own public `/mcp` endpoint, and an MCP Tool must not be the sole owner of business logic required by Admin. A common domain operation model does not itself mean an Admin UI for every downstream operation has been implemented.

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
| Concurrency | active per-principal/Target/workflow jobs/connections | separate from accumulated Job history and operation lifetime |
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

### ChatGPT file-parameter ingress to a selected Target (Gateway source candidate)

The **`target-file-input`** MCP tool accepts a top-level `file` parameter
advertised as `_meta["openai/fileParams"]=["file"]`. The original
**`wordpress-file-input`** stays as a backwards-compatible WordPress-only
entrypoint. Both use the same FileParams shape: required `file_id` and
`download_url`, optional `mime_type` and `file_name`. This is a
**host-input capability declaration, not proof** that a particular ChatGPT
connection injects or returns a real attachment. The host and actual connected
client must be tested separately.

**Host-specific capability advertisement (review A2):** the OAuth-verified
`chatgpt` client profile, **not** an untrusted MCP `clientInfo`, gates
`openai/fileParams` Tool discovery. No file-input Tool is advertised to
other approved OAuth client profiles. The legacy WordPress Tool is listed only
when the same Gateway principal has at least one currently connected, unpaused
WordPress Target, stored provider credentials, and both exact destructive and
readonly WordPress-Ability permissions; the generic Tool is listed when that
mode or an eligible SSH/SFTP write mode exists. A connected SSH Target must
have its registered SSH config and credential, an effective `ssh.file.write`
grant, and enabled optional SSH whole-file mode. The generic Tool's `mode`
enum contains **only** locally eligible modes. Discovery performs **no**
Bridge/SFTP network call and cannot promise downstream Builder Write,
`upload_files`, private staging directory or fresh OAuth validity: all
provider and dynamic permissions are rechecked **before signed-file GET** and
at the effectful operation. The connected ChatGPT Tool catalogue must be
refreshed after any local Target/grant/feature change; absence from discovery
is not a retained access grant. This is deliberately conservative optional
capability discovery, not a new authorization system.

Shared ingress validates the exact signed HTTPS origin
`files.oaiusercontent.com`, public A/AAAA DNS, pinned peer IP and verified
TLS hostname/certificate. No redirects, embedded authentication, fragment,
arbitrary URL origins, decompression or secret-bearing logs are allowed. The
opaque signed query is forwarded unchanged and never included in a response.
The existing ordinary 8 MiB JSON HTTP response ceiling is **not increased**:
file bytes are captured in a separate bounded private spill-to-disk stream
(64 KiB memory threshold) with an independent whole-object budget, exact
byte count and SHA-256. Any incomplete, encoded, expired or over-budget
download fails closed before creating a Target artifact.

The caller explicitly selects `target_id` and exactly one mode:

- **`wordpress_media_stage`** (or legacy `wordpress-file-input`):
  admits only the selected authorized WP AI Bridge Target, preflights the
  exact destructive private-transfer permission and its readonly
  `bridge-info.access_groups.builder_write` and
  `site-context.current_user.capabilities.upload_files` projections
  **before downloading the signed URL**. Both Gateway readonly and
  Bridge Site Read must also be permitted. Real `begin(media)`,
  `append` and `verify` re-authorize and require receipts with the same
  transfer ID, purpose, length, digest, progress and complete state.
  The result is an **unpublished, expiring private lease only**. A native
  Media import is impossible through file-input; it requires a separately
  authorized `wordpress-ability-execute` /
  `wp-ai-bridge/transfer-media-import` with the originally returned
  `transfer_id`, subject to the Bridge's immutable one-way import claim.
  Never replay a possibly committed native import or silently create a new
  lease to claim its original effect succeeded.
- **`ssh_sftp_upload`**: only when the installed SSH whole-file
  feature is enabled, the current selected Target is `ssh_direct`, and
  the principal has the exact `ssh.file.write` grant and no Target Pause.
  Before downloading, the exact selected Target must still be Connected
  and unpaused, with registered SSH configuration, a current
  `ssh_auth` credential and a locally decryptable, endpoint-bound secret
  available. This check makes NO remote SSH connection or signed-file GET.
  A different eligible Target never substitutes for a disconnected,
  reconnect-required, misconfigured or credentialless selected Target.
  After download, the same readiness/grant check and the effect-time
  SFTP authorization apply independently. The caller
  supplies a specific absolute destination `path` and an already existing
  private, same-filesystem 0700 `private_staging_dir`. Optional
  `overwrite=true` is explicit last-writer-wins; optional paired
  `expected_size`/`expected_mtime` are **best-effort only**.
  After download, the Target/grant is rechecked; the existing SFTP
  streaming engine authenticates again, stages privately, verifies exact
  bytes and SHA-256 by remote readback, and publishes atomically. It never
  runs an SSH shell command, opens a generic file store, or replaces a file
  in create-only mode. An uncertain post-dispatch write reports
  `possible_remote_effect` and `retry_safe=false`; inspect the exact
  destination before retrying manually.

**Per-mode, finite budgets:** WordPress signed-file admission defaults to
8 MiB and 120 seconds, set in the private environment as
`CHATGPT_WP_FILE_MAX_BYTES` (source maximum 64 MiB) and
`CHATGPT_WP_FILE_MAX_SECONDS` (source maximum 120 seconds).
Its deadline covers signed download **and** provider private staging; the
provider may impose a stricter quota or expiry. The separate SSH mode reuses
the existing Owner Admin-configurable `ssh_transfer_max_kib` and
`ssh_transfer_max_seconds`, with source maximum 64 MiB and 40 seconds.
SSH's overall file-input deadline covers signed download and SFTP write,
not two independent full time budgets. **Every signed file download
must first acquire a short-lived, database-serialized global temporary-storage
and concurrent-transfer reservation.** The shared defaults are four concurrent
admissions, at most two WordPress and two SSH, with 128 MiB of aggregate
worst-case reserved local spool space. `CHATGPT_FILE_MAX_ACTIVE`,
`CHATGPT_FILE_WP_MAX_ACTIVE` and `CHATGPT_FILE_SSH_MAX_ACTIVE` are
private operator-configured integers clamped to 1–16. Shared
`CHATGPT_FILE_MAX_RESERVED_BYTES` is clamped to 1–512 MiB.
For WordPress, reserve the entire per-file byte maximum for **one** local
`php://temp/maxmemory:65536` stream. This is a physical-spool invariant:
`SafeHttpClient::streamChatgptFile` attaches its bounded write filter
**directly** to that fresh caller-owned stream. It must NOT create an
independent `BoundedResponseBody` stream or buffer the entire signed HTTP
response and later call `stream_copy_to_stream`, because that would
temporarily double WordPress disk use without an accompanying reservation.
Non-200 status, unacceptable Content-Encoding, Content-Length/actual-length
mismatch, byte-limit breach, timeout and transfer failure discard this
private, never-published stream; `ChatGptFileIngress` owns the eventual
hash/byte verification and cleanup.

SSH reserves **twice** its per-file byte maximum because its verified SFTP
upload allocates a second temporary stream, after the HTTP receive stage,
while the original received source stream remains open. These phases have
a maximum of two concurrent local spools, never three. Reservations
are pessimistic, independent of untrusted Content-Length, and count ALL
in-flight WordPress/SSH FileParams requests across PHP workers and
Gateway nodes sharing the authoritative MariaDB/MySQL database.

The new `chatgpt_file_admission_guard` singleton and
`chatgpt_file_admission_leases` table are created by the **v2.3.5 migration**.
An atomic row lock serializes checking the configured global active count,
per-mode count and aggregate reserved bytes before admitting a new lease.
A refused/oversubscribed, missing-migration or unavailable-DB request
**does not fetch** the signed URL; errors are bounded and reveal no URL.
The reservation spans the signed-file download AND Target operation, is
released in `finally` after spools close, and has an automatic PHP teardown
fallback. If a process dies or the DB is unavailable during release,
expired non-content leases are pruned on the next successful admission after
the per-mode deadline plus a 30-second reconciliation grace. Lease records
contain only random IDs, mode, byte quota and expiry—not file IDs, URLs,
pathnames, Target, user, payload or credentials. This is an **admission
ledger**, not a new file store or background daemon. The Gateway nodes must
use the same database and synchronized clocks. Changing quotas while
transfers are active does not retrospectively cancel them; new
admissions enforce current limits.

Linux FD-level >64 KiB synthetic HTTP fixture tests verify that the
actual Guzzle response sink IS the caller's private PHP stream, exactly
one disk-backed spool is open at each observed network chunk for WordPress,
and exactly two are open during SSH `VerifiedTransferSpool::capture`.
The one-megabyte aggregate-capacity regression checks a real WordPress
signed-file download and refuses a second signed GET while full. Separate
MariaDB-process tests prove atomic admission; neither fixture alone is
proof of a live host-installed ChatGPT attachment.

Host PHP/FPM workers, temporary disk, proxy and transport limits may be
stricter; accounting reserves an upper bound **among Gateway FileParams
requests**, but cannot preempt arbitrary host processes consuming the
temporary filesystem. No setting reserves full maximum memory or
promises durable resume. WP budget is currently a private
environment knob, not a new Admin setting; existing SSH budget controls
remain unchanged. Neither maximum is a Gateway-wide universal file limit.

For both modes, client filename/MIME metadata remains untrusted and is not
authorization to install, unpack, execute or import packages. A source failure
before an effectful stage must not create a native artifact. Missing or
inconsistent post-dispatch receipts are **unknown**, not success or
automatically retryable. Temporary PHP spools close on every success/failure;
WordPress lease cleanup/expiry and SSH remote temporary cleanup belong to
their existing Target providers. Source tests and isolated Gateway-to-Target
bytes do not prove a live ChatGPT `openai/fileParams` injection.

**Not implemented by this input adapter:** native ChatGPT **output attachment**
creation, generic WordPress binary whole-file API, multi-GiB/resumable
transfer, WordPress WXR import, plugin/theme execution, or any production
rollout. Existing authorized client-compatible Bridge file-byte reads and
SSH ranged/whole-object downloads have distinct receiving-host support;
Base64 in MCP JSON is not automatically a user-downloadable file.
Real host acceptance and the reverse client/model receipt remain tracked by
[Gateway #147](https://github.com/AChWorks/mcp-gateway/issues/147)
and [Bridge #134](https://github.com/AChWorks/wp-ai-bridge/issues/134).

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
