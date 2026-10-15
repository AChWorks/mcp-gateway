# Whole-file binary data plane — Issue #147 (released in v2.1.2; OFF by default)

**Public release status:** [v2.1.2](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.1.2) includes the implementation from independently HIGH_ASSURANCE-approved [PR #166](https://github.com/AChWorks/mcp-gateway/pull/166). This is a **published code/package capability, not a production installation or default enablement**. `SSH_FILE_TRANSFER_ENABLED=false` keeps the optional HTTP route **OFF** until a separately authorized real-host security/proxy/resource check enables it. Independent PHP/Python clients proved bidirectional bytes and SHA-256 on disposable installed fixtures; this does **not** prove native ChatGPT model file handoff. The earlier v2.0.3 maintenance release did not contain the route.

## Browser file picker fallback — source candidate for #181

This is a **development candidate, not part of v2.2.1**. On an authenticated
Gateway Administration session, open **Targets → exact Direct SSH Target**.
If the Target has a credential, the active user has `ssh.file.write` and/or
`ssh.file.read`, and the separately approved server environment has
`SSH_FILE_TRANSFER_ENABLED=true`, an HTML file picker offers an upload
and a remote-path form provides a browser attachment download. These Admin
forms call the existing verified SFTP whole-file service; they do **not**
issue OAuth access tokens or expose new unauthenticated data-plane endpoints.

The browser must upload a real local file, select the exact absolute remote
destination and enter a **pre-provisioned owner-controlled 0700 private staging
directory on the destination's filesystem**. Gateway validates target-specific
permissions before dispatch, computes local bytes/SHA-256, verifies remote
readback before atomic create/replace and never echoes file contents or
private paths to logs. User-selected overwrite is explicitly last-writer-wins
rather than a compare-and-swap operation. For downloads, Gateway verifies
remote size/SHA-256 before producing an attachment, supplies verification
headers and disables content sniffing. Browser or network interruption
requires separately verifying the remote state; never auto-repeat uncertain
writes. PHP `upload_max_filesize`, `post_max_size`, proxy and request-timeout
settings can be stricter than the 64 MiB Gateway maximum.

Native ChatGPT chat attachments still **do not automatically become MCP
tool input**, and these browser forms do not return ChatGPT-model-readable
file artifacts. They are a practical user-initiated supported-interface
fallback, not evidence of native host support. The flag must remain OFF on
production until a separate authorized rollout and real-browser/SSH
acceptance. A non-Owner with explicit read/write Target grants is eligible
to use the forms; permissions are not broadened by the UI.

## Proven contract and what it does not claim

An approved MCP application obtains its usual OAuth access token and chooses
a registered authorized SSH Target. The **same signed bearer** is sent over
TLS to these optional binary sidecar routes:

| Method | Endpoint | Body and successful result |
| --- | --- | --- |
| POST | `/mcp/file-transfer/ssh/{targetId}/upload` | Raw `application/octet-stream`, `201` structured JSON with verified count + SHA-256 |
| POST | `/mcp/file-transfer/ssh/{targetId}/download` | Small `application/json` selector, `200` actual `application/octet-stream` attachment with verified count + SHA-256 headers |

The ordinary `/mcp` MCP JSON-RPC transport continues to serve Target
discovery, authorization metadata, WordPress native Abilities, and bounded
SFTP range/stat/commands. The binary sidecar is **not itself an MCP Tool or
an MCP Resource**. A client must deliberately use its authenticated HTTP
binary-capable transport in addition to MCP control-plane calls. The official
PHP MCP SDK and a separate Python standard-library HTTPS/JSON-RPC client
demonstrate this combination in an actual installed disposable environment.
The **ChatGPT host/model file-upload or attachment handoff remains unverified
and must not be advertised**.

The initial whole-file Target is **`ssh_direct` only**, because the installed
OpenSSH/SFTP Target exposes an actual seekable byte-stream backend. The
WordPress Target still has its existing authorized **native Abilities**,
including WordPress-owned media operations where available; it does **not**
currently advertise a raw binary whole-file Target interface. No duplicate
WordPress media/plugin manager or insecure PHP filesystem bypass is added.
AI Server Agent Issue #111 remains paused and unchanged.

## Discover supported transfer modes through ordinary MCP

**Do not hardcode the sidecar route in future AI clients.** Call the already
available `target-context` MCP tool with the explicitly selected authorized
`target_id`. Its additive `target.file_transfer` field is a permission-
filtered capability catalog, with `schema_version=1`,
`whole_file_modes`, `native_interfaces`, and an explicit
`model_file_consumption_verified=false`. An unauthorized Target yields the
same `target_not_found` response as a nonexistent one; a visible but
read-denied/write-denied Target never advertises that operation.

For an SSH Target **only when the feature is enabled** and the user has
the relevant SSH grant, `whole_file_modes` contains
`id=ssh_https_raw_binary_v1`. The mode carries the exact
`endpoints.upload.path` and/or `endpoints.download.path` (each `POST`),
`auth=current_oauth_access_token_bearer`, actual current Owner-
configured `max_object_bytes`, `max_operation_seconds`,
`integrity=exact_bytes_and_sha256`, and `resume=false`. **Paths are
relative to the authenticated MCP resource origin**: construct neither
an untrusted host nor a Target-supplied absolute remote URL. A client
may use this mode only if it can make separate, authenticated HTTPS
binary requests and locally verify every returned octet and SHA-256.
The advertised Gateway profile does not override stricter
client/proxy/Target limits or promise that a chat host can ingest
attachments.

Even with the binary mode disabled, `native_interfaces` documents
the already operational 16 KiB **per-call** SSH read window and atomic
single-window write. Read windows can address a larger file with
size/mtime *best-effort* consistency; repeated write calls are **not**
an append/resumable whole-file API. An authorized WordPress Target
instead advertises its existing dynamically discovered native Ability
tools, with **no SSH max-object limit inherited** and **no fabricated
raw whole-file HTTP mode**. This does not whitelist downstream Ability
names, bypass WordPress-native permissions or claim that a WordPress
Media Ability is a universal binary interface. A future connector may
advertise a wholly different real transfer mode.

The real installed PHP MCP SDK client **and independent Python
JSON-RPC MCP client** now first discover and validate this same catalog
through `target-context`, then send and receive binary bytes over the
advertised authenticated SSH paths. The sidecar is still not an MCP
Resource or an automatically invoked Tool; a host unable to send/receive
raw HTTPS bodies must use an actually supported native mode instead
of treating the catalog as a promise of file delivery.

### Compatibility reference: AI Server Agent (READ-ONLY comparison)

As of Agent main `d0f98848513bc518b9dd4f8397c089bf3f1acf81`, the
**standalone** Agent's own `workspace_transfer` MCP tool provides
`begin/chunk/status/commit/abort`, stable idempotency keys, sequential
up to 256 KiB decoded Base64 chunks, per-chunk and whole-object SHA-256,
durable offset/TTL, bounded 4 MiB preparation windows and atomic
version-preconditioned publication. Its independent `workspace_stat`
and `workspace_read` paths support version-pinned outbound byte windows
up to 128 KiB in the tested SDK client. The Agent defaults to **512 MiB
cumulative staged storage**, 8 active sessions and 3600-second TTL,
with separately configurable limits. A 33 MiB object has been covered by
the Agent's separate isolated executable acceptance; that is **not**
evidence of successful routing through Gateway or a ChatGPT attachment.

**Future connector invariant:** The Gateway must preserve downstream
Agent session keys, offsets, commit receipts, user/workspace authority
and error/unknown-outcome semantics if a real Agent connector is
approved. Its staged logical operation is **not** constrained by this
Gateway's 16 KiB inline SSH tool window, 64 MiB synchronous SSH profile,
40-second SFTP primitive, or WordPress HTTP response limits. The
Gateway may have finite **per MCP call** framing/admission safeguards,
but must not silently reclassify a series of authorized bounded Agent
calls as one SSH binary operation. Keep logical lifetime, per-call
windows, aggregate staged bytes and connected-host capability distinct;
select an actually implemented downstream mode. Do not duplicate the
Agent's durable journal or security engine in Gateway merely for proxying.
Agent Gateway integration remains separately Owner-paused under
[Issue #111](https://github.com/AChWorks/mcp-gateway/issues/111),
so **no Agent connector, pass-through or long-running Agent file mode is
claimed in this PR**.

## Auth and request representation

Existing `RequireMcpAccessToken` middleware validates signed OAuth access
tokens, expiry, active approved client profile, scope and enabled Gateway
user. `AccessControl` resolves the exact Target and checks its scoped
`ssh.file.write` or `ssh.file.read` permission. Wrong user, forbidden or
non-SSH Target is not enumerable via these endpoints. Signed bearer and
Target grants are reevaluated on **every** new binary request.

### Upload

`Content-Type: application/octet-stream` and an exact decimal
`Content-Length` are required. Send one short
`X-Gateway-Metadata` header: unpadded, canonical base64url of a JSON object
with these keys:

```json
{
  "path": "/home/deploy/example.zip",
  "private_staging_dir": "/home/deploy/.gateway-transfer-private",
  "size": 1048576,
  "sha256": "<64 lowercase hex SHA-256 digits>",
  "overwrite": false
}
```

Optional **paired** `expected_size` and `expected_mtime` apply only to an
intentional overwrite. `path` and `private_staging_dir` must be absolute
valid SFTP paths. The pre-provisioned staging directory must be on the same
filesystem as destination, mode **0700**, owned by the SSH principal. The
streaming engine verifies ownership and mode of each private temporary inode
**before** accepting payload bytes. It verifies submitted length and SHA,
reads the temporary file back and verifies remote SHA before atomic
create-only hardlink or explicit POSIX replacement. An overwrite is
last-writer-wins with optional best-effort size/mtime check, **not** CAS.
A duplicate create-only request is rejected, never silently replayed.

Do **not** place credentials or arbitrary file bytes in the metadata header,
MCP tool arguments or URL. Authentication goes in the `Authorization:
Bearer` header over TLS.

### Download

Send `Content-Type: application/json`, accurate `Content-Length` and a
small JSON body:

```json
{"path":"/home/deploy/example.zip","expected_sha256":"<64 lowercase hex SHA-256 digits>"}
```

`expected_sha256` is optional; paired `expected_size` and
`expected_mtime` may also be supplied. The Gateway completes the
source-to-private-spool SFTP read **and SHA-256 verification before HTTP 200
headers**. It then returns actual bytes with `Content-Length`,
`X-Gateway-File-SHA256`, `X-Gateway-File-Bytes`,
`X-Gateway-Target-Id`, `X-Gateway-Snapshot`, `Cache-Control: no-store`
and `X-Content-Type-Options: nosniff`. The client **must** save bytes and
check local SHA-256, exact byte count and HTTP status; a partial HTTP 200
body is **not** success. Streamed attachment bytes are not automatically
made visible to any model or chat host.

The source is re-statted for matching size/mtime before and after SFTP read;
this is *best effort* rather than a remote filesystem snapshot token. An
expected SHA-256 rejects stale/different bytes, but cannot promise atomic
read snapshots under concurrent same-size/same-mtime external writes.

## Quotas and resource behavior

All knobs extend the **existing** Owner-only typed, audited, password-
confirmed `OperationalSettings` service, not a duplicate config/ACL system:

| Axis | Source/env fallback | Owner override | Immutable profile boundary |
| --- | --- | --- | --- |
| Complete SSH object, both directions | `SSH_FILE_TRANSFER_MAX_BYTES=8388608` (8 MiB) | `ssh_transfer_max_kib` (256–65536 KiB) | 64 MiB max for *this synchronous SSH profile only* |
| SFTP+PHP synchronous operation | `SSH_FILE_TRANSFER_MAX_SECONDS=30` | `ssh_transfer_max_seconds` (5–40 seconds) | 40 seconds in existing SFTP stream primitive |
| Transient in-memory spool | <=64 KiB before disk spill, 64 KiB SFTP write block | No new independent setting | Private `php://temp`, unlinked on close |
| Per-Target SFTP admission | 30 file operations / 60 sec | Existing enforced policy | Serialized per-Target lease (90 sec); no bypass |
| OAuth/MCP framing | Existing separately validated limits | Separate WP settings | No increase in 16 KiB MCP inline SFTP window or WP decoded HTTP guard |

The configured maximum is **not** allocated on ordinary requests. One
upload/download operation stages at most one configured object in the Gateway
temporary stream at a time, then closes it on completion/error. Concurrency
is bounded by the existing per-Target SFTP admission, server HTTP request
throttles and independent PHP-FPM/webserver worker, request-body, temp-disk
and client send/receive timeouts. Those **host/proxy settings must be audited
per deployment**; this source does not by itself prove an arbitrary client
or proxy will hold a streaming HTTP connection open for 40 seconds or that
host-level stalled socket reads/writes can be interrupted by PHP. In
particular this is not a multi-GiB transfer or durable resume service.
Other Target types and future transfer modes can have different measured
profiles; these SSH bounds are **not a universal Gateway file-size limit**.

The established synchronous process uses an aggregate monotonic deadline.
A client that does not receive all `Content-Length` bytes within its own
finite deadline must discard the partial local download.

## Failure, retriability and privacy

| Failure | Client result / recovery |
| --- | --- |
| Missing, invalid, expired, disabled-client or revoked-user OAuth bearer | HTTP 401; re-authorize appropriately |
| Wrong/inaccessible Target, user or operation | HTTP 404 `target_not_found`, no Target enumeration |
| Wrong request shape or source byte count/hash | HTTP 422; fix metadata/input and send a new request |
| Complete size exceeds selected SSH Owner budget | HTTP 413 `file_too_large`; choose another approved delivery mode or Owner-adjusted capacity |
| Expected remote SHA/version changes; file already exists; unsafe private staging | HTTP 409; inspect Target and re-evaluate before another mutation |
| SFTP/remote mutation became uncertain after dispatch | HTTP 409 `outcome_unknown`, `possible_remote_effect=true`, `retry_safe=false` and `temporary_cleanup_confirmed` when known; **never auto-retry** |
| SFTP or HTTP request exhausted finite budget | Timeout/bounded error; inspect remote effects after a write before retry |
| Existing per-Target SFTP admission reached | HTTP 429 `rate_limited`, `Retry-After: 60`; back off instead of retrying immediately |
| Concurrent same-Target SFTP operation or unavailable admission backend | HTTP 409 `connection_busy` or HTTP 503 `admission_unavailable`; inspect/retry within a finite budget |
| Download interrupted *after* HTTP 200 begins | Client detects incomplete body/digest; discards local spool; no server-side persistent resumable handle |

Application activity records capture sanitized operation, Target, outcome
and correlation ID, not raw payload bytes, SSH path secrets, request headers
or signed bearer tokens. No public file location, object store, permanent
download link, shared mutable Target temp directory or background polling
service is created.

## Reproducible real installed acceptance

From an exact **clean committed** candidate checkout in a disposable
authorized Linux server, with the existing pinned WordPress/Bridge/Adapter
release inputs, PHP/Composer, MariaDB, OpenSSH, `unshare`, `socat`,
`ip`, WP-CLI and root privilege:

```sh
sudo bash tests/Support/installed-mixed/run.sh
```

The runner uses `git archive HEAD` and installs dependencies against the
committed `composer.lock`, regenerates keys, creates a private network
namespace and disposable SSH user/database, then cleans both on completion.
See `docs/INSTALLED-MIXED-WP-SSH-ACCEPTANCE.md` for input pins, safety
and exact root cleanup. **Never run against user/production WordPress or
SSH hosts**.

The test creates two actual independent external clients: (1) official PHP
MCP SDK over verified HTTPS plus a Guzzle raw binary sidecar consumer;
(2) Python 3 standard HTTPS/JSON-RPC MCP with its own MCP session and a
file-backed, incremental binary HTTP sender/receiver (not the PHP SDK).
It verifies empty, UTF-8, PNG, PDF, ZIP, 256 KiB and >1 MiB opaque files,
remote SFTP stat and client-side SHA/length parity, invalid/disabled/revoked
identities, cross-Target scope, refused path, rejected wrong length/digest,
stale source SHA, duplicate non-idempotent create, actual over-budget bytes,
and private cleanup. The pre-existing detailed SFTP fixtures cover
post-dispatch uncertainty, interrupted read/write, unsafe staging and
disconnect behavior. Tests run within the production-equivalent 30 SFTP
operations/minute admission budget; a legitimate `rate_limited` does not
authorize raising the production limit.

Inspect only sanitized outputs in the emitted `real-installed-mixed-112-*`
evidence directory: `identity.txt`, `file-client.json`,
`python-file-client.json`, `file-revoked.txt`, `report.json` and
`cleanup.txt`. Source HEAD/tree, exact installed software versions,
effective limits, file sizes/digests/timings, memory peak and cleanup are
recorded. Do not copy ephemeral signed client tokens, SSH passwords,
private keys, MariaDB files or test users into GitHub.

## Integration and operational readiness boundaries

The optional HTTP wire/security contract was accepted in independently reviewed [PR #166](https://github.com/AChWorks/mcp-gateway/pull/166) and **released as disabled-by-default code in v2.1.2**. It is not evidence of a production deployment. Before enabling it on a *specific* supported hosting profile, follow the [deployment pre-enablement checklist](DEPLOYMENT.md#optional-ssh-whole-file-data-plane-released-but-disabled-host-acceptance-pending): request-body/worker/proxy timeouts, temporary-disk and concurrent-upload budgets, verified TLS, remote private SFTP staging, and client-side full-file verification must be measured, not assumed.

**Ingress resource boundary (independent review OPTIONAL O1):** inbound HTTP
bytes can occupy one PHP temporary spool *before* the per-Target SFTP
admission lease is obtained. That lease serializes **remote SFTP work**,
not aggregate concurrent HTTP staging. Bound worker count, accepted body
size, client timeouts and spill storage on the real hosting profile; add
earlier aggregate ingress admission only if measurements justify it,
without a second quota engine or unnecessary new processes.

**Outgoing audit semantics (review OPTIONAL O2):** the server records
successful **remote read and verified local staging** before its HTTP
download callback finishes streaming to the client. This audit event
does **not** certify complete client receipt. The receiving client must
verify exact `Content-Length` and SHA-256 and discard incomplete data;
never claim delivery from a server-side staging event alone.

Not covered: ChatGPT host-native attachment/model handoff, WordPress
whole-file binary transport, Agent routing (Owner-paused #111), durable
SSH partial-write resume, retained download jobs, true remote snapshots,
multi-GiB files or arbitrary proxies/shared hosts. Report these as
**unsupported/unverified**, not completed. #147 and #154 retain distinct
remaining host/client/capacity evidence; #112 owns release and
production-host acceptance.
