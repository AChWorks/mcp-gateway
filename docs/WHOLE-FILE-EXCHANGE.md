# Whole-file binary data plane — Issue #147 (draft, not released)

**Status:** Source-only candidate on Issue #147. Requires an explicit Owner
protocol/security-contract decision before public enablement. The default
`SSH_FILE_TRANSFER_ENABLED=false` keeps this extension OFF. It is **not**
part of the public `v2.0.3` release and no production site was deployed.

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

## Owner decision / readiness boundary

This is a **new optional HTTP protocol contract**, not previously part of
the released MCP API. The Owner must decide whether the exact sidecar
paths, bearer binding, base64url metadata + raw body shape, response
integrity headers, host timeout prerequisites and 0700 SSH staging
provisioning are an acceptable supported public contract. Until this
decision, leave the feature disabled; do not merge, release or deploy.
Independent author-separated review is also required before merge.

Not covered by this implementation: ChatGPT host attachment/model file
hand-off; provider-native WordPress whole-file binary ingress/egress;
resumable partial writes; durable download jobs; true filesystem snapshots;
multi-GiB files; untested proxies/shared hosts. Report these as
**unsupported/unverified**, not completed.
