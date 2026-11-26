# ArvanCloud API connector — dynamic REST/OpenAPI Target

## Purpose and truthful support boundary

The built-in `arvancloud` connector attaches **one registered HTTPS API root** to a Gateway Target, encrypted Machine User API key and the existing Gateway User/Group/Target/AI client authorization model. It does not deploy a second service, register arbitrary external MCP servers, or expose a credential-forwarding proxy.

The stable MCP operation surface is:

- `arvan-api-catalog`: read an **optional** public OpenAPI 3.x JSON/YAML description from the configured URL and page/filter path, method, parameters and requestBody. A description is explanatory, not executable authority.
- `arvan-api-request`: call the selected Target's **registered** API origin/base path with a relative path, HTTP method, optional structured query, JSON or provider-defined text content types, URL-encoded form fields, and multipart form/file parts. It works with newly released compatible HTTP endpoints **even if OpenAPI metadata has not yet been updated or provided**.

An Arvan REST API change to paths, query arguments, JSON schemas, compatible request content types or HTTP methods should not require a Gateway release. A different *origin* or API version/base path is a Target configuration change and may require a different key. Different authentication protocols, provider-side signing (such as S3 AWS Signature V4), resumable uploads, or large-file streaming require additional adapter capabilities; they cannot be safely promised by arbitrary REST read/write alone. Ordinary multipart form requests with inline file parts are supported.

Current authenticated request profile: `Authorization: Apikey <key>` over HTTPS, JSON/text/form/multipart requests and fixed selected Target. Ordinary responses are held in a bounded in-memory buffer; binary downloads and very large uploads require a separate streaming/file contract. The selected Machine User's real Arvan-side API scopes remain authoritative. Header name/prefix are deliberately connector-owned and do not come from MCP arguments; a different authentication contract needs an explicitly reviewed provider adapter change.

## Enroll from Gateway

1. In ArvanCloud, create a **Machine User** with appropriate provider-side Access Policy and generate an API key. Never paste it into ChatGPT, a GitHub issue, PR or log.
2. In Gateway, sign in with **targets.create** permission. Navigate to **Targets → Add Target → ArvanCloud API**. Enter a stable Target ID and label.
3. Enter the specific product's **API base URL**, including a version prefix if required, e.g. `https://napi.arvancloud.ir/cdn/4.0`. Each other API root, product or region can have its own registered Target without code changes.
4. Optionally enter the product's **public OpenAPI YAML/JSON description URL**, e.g. `https://www.arvancloud.ir/api-docs/cdn-4.0.yml`. No API key is ever sent to that documentation endpoint. You can leave it blank; request execution does not require it.
5. **Optionally** enter a **known authenticated read-only GET probe path**, e.g. `/domains`, if the selected product exposes a safe GET that requires the Machine User key. Do not guess an endpoint or use a GET with side effects. The probe is not required for registration, saving a key, API requests or HTTPS reachability checking.
6. Select Direct or an available Connection Relay in the shared Target details. Enter the API key and your current Gateway password. Submit, assign Gateway Target or Target Group access as intended, then open Target details. **Check HTTPS endpoint (no API key)** sends only `HEAD` to the saved API root (with a trailing `/`) and reports an HTTP response/transport failure. HTTP 3xx/401/403/404/405 proves only that an HTTPS peer responded, *not* that a product API path is valid or that the Machine User key works. Starting with v2.7.2, the no-key HEAD check reports a 3xx HTTP status as **HTTPS peer reachability only**; it never follows the redirect or its untrusted `Location`. The historical immutable v2.7.1 package instead reported such a response as `unsafe_redirect`. Authenticated GET and ordinary API requests always reject HTTP redirects. This check never changes `connection_state`. **Verify API key (read-only GET)** appears separately when both a key and a configured read-only probe exist; success only verifies that exact authenticated GET at the time of testing.
7. Connect ChatGPT to the Gateway using the existing OAuth setup. As an authorized Gateway user, call `targets-list`, `target-context`, `arvan-api-catalog`, then `arvan-api-request`. Set and enforce Target-specific grants through the existing Admin controls.

The key is encrypted inside the existing `target_credentials` model and is bound to immutable Target record ID, public Target ID and exact approved API base URL. It is never returned to the client. Replacing the API origin requires scoped configuration permission, a **new** key and the acting user’s current Gateway password; replacing a key resets the previous connected evidence. A selected Relay applies equally to the public OpenAPI document, unauthenticated HEAD, authenticated GET verification and every API request/body format. Changing the route resets verification without deleting the origin-bound key; an unavailable Relay never silently falls back to Direct. **Disconnect** deletes only the local key; revoke the original Machine User key in ArvanCloud separately when needed.

## Request examples

Inspect a catalog:

```json
{"target_id":"arvan-cdn","offset":0,"limit":20,"search":"dns"}
```

Read a domain list using the configured CDN API root:

```json
{"target_id":"arvan-cdn","method":"GET","path":"/domains","query":{"page":2}}
```

A JSON mutation (shown as a **shape example**, not authorization to execute it):

```json
{"target_id":"arvan-cdn","method":"PATCH","path":"/domains/EXAMPLE-ID/config","body_json":"{\"enabled\":true}"}
```

Additional provider-defined request bodies:

Kubernetes YAML apply patch (the caller must have `arvan.api.write` and select the appropriate CaaS Target root):

```json
{"target_id":"arvan-caas","method":"PATCH","path":"/apis/apps/v1/namespaces/demo/deployments/sample","content_type":"application/apply-patch+yaml","body_text":"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: sample\n"}
```

A JSON Patch body can use `body_json` together with `content_type: "application/json-patch+json"`. Other valid provider media types are supported for text bodies without an endpoint-specific allowlist.

URL-encoded form fields for an older Swagger 2 endpoint:

```json
{"target_id":"arvan-vod","method":"POST","path":"/tags","form_fields":{"title":"example"}}
```

Multipart form upload for a modest public text/BIND file (base64 here is a placeholder for the actual bytes):

```json
{"target_id":"arvan-cdn","method":"POST","path":"/domains/example.test/dns-records/import","content_type":"multipart/form-data","form_fields":{"overwrite":"true"},"form_files":[{"name":"f_zone_file","filename":"records.txt","content_type":"text/plain","content_base64":"BASE64_OF_FILE_BYTES"}]}
```

An optional `accept` media type (such as `text/plain`) changes only the standard response `Accept` header; it never changes the Target origin, credential or Authorization header. Response bytes returned by this tool must fit the configured in-memory API response budget.

Choose exactly **one** body representation: `body_json`, `body_text` (requires `content_type`), or `form_fields` / `form_files`. File parts are inline base64 only, not filesystem paths, fetch URLs or remote file handles. When file parts exist, the Gateway generates the multipart boundary. `content_type: "multipart/form-data"` also allows multipart without files. The API request parameters never select credentials or the destination host. Base64-in-JSON is **not** a practical large-object transfer or a private-key exchange mechanism: use a separately reviewed private staging/streaming workflow for large or sensitive files.

Swagger 2 `body` / `formData` and OpenAPI 3 `requestBody` descriptions expose method, path, parameter, media-type and file-field hints. They are **descriptive only**; the Gateway does not infer an authorization grant from a document.

Never put the API key, `Authorization` header or a full URL in tool arguments. Method and relative path are caller inputs; **destination host, key and transport policy are not**. The registered API base path cannot be escaped with `..`, encoded slash/backslash or `//` authority replacement.

## Permissions, effects and safety

These are additional **Target-scoped** permissions. All still require a role ceiling, effective selected/group Target scope, explicit deny precedence, AI-access/OAuth client authorization, and a non-paused Target:

| Permission | HTTP methods |
| --- | --- |
| `arvan.api.inspect` | Inspect configured public OpenAPI document |
| `arvan.api.read` | `GET`, `HEAD`, `OPTIONS` |
| `arvan.api.write` | `POST`, `PUT`, `PATCH` |
| `arvan.api.destructive` | `DELETE` |
| `arvan.api.unclassified` | Any other supported non-TRACE/CONNECT method (requires high-trust grant) |

This *HTTP-verb* classification is provisional: a provider API that uses `POST` to **delete** must be treated as destructive by the caller, and API key restrictions should cover it; the Gateway does not infer safe business effects from arbitrary provider documentation. Existing admin permission groups remain effective. The Gateway checks live Target grants, stored key/binding and Target pause immediately before dispatch. Admin **Connect**, **Reconnect**, and **Test** all respect the same fresh Pause boundary; **Disconnect** remains available for local credential removal during a pause. A successful explicitly requested authenticated GET probe changes the recorded connection state only if its exact API configuration and encrypted credential remain unchanged at the moment of settlement. A concurrent rotation, disconnect or pause invalidates the old probe evidence; the database lock is held only for the final local state check, not across HTTP I/O. The separate unauthenticated HTTPS `HEAD` check is permitted by the same Target Test grant, respects the same Pause fence and registered destination, never sends an API key and **never writes connection verification**. A concurrent API-root change invalidates even the displayed HEAD result. If the API root, key or probe is changed, previous `connected` evidence is reset to `disconnected`; ordinary authorized API requests can still succeed with HTTP 200 without automatically promoting this separate verification state. Use the optional known-safe GET to establish fresh authenticated proof, not an invented default provider endpoint.

An uncertain mutating request or provider non-2xx response is recorded as **unknown**; do not automatically retry until remote state has been reconciled. The existing scoped Activity/diagnostic lookup retains the method, selectively redacted relative path, SHA-256 path fingerprint, observed HTTP status, and available provider request ID for **success, provider failure, and transport-uncertain outcome**. Credential-equivalent URL encodings (including partially and repeatedly percent-encoded values), JSON-escaped slashes/Unicode, and mixed URL-then-JSON representations are inspected before persistent diagnostics or provider data are returned. An affected opaque response body or request ID is replaced with `[REDACTED]` when its safe fields cannot be retained reliably; unrelated path segments, status, method, path fingerprint and safe request IDs remain available. Sanitization never modifies the outbound request URL, request body or authorization header. It intentionally does **not** store API keys, query parameters, request bodies, Authorization headers or full external URLs. Find the matching diagnostic reference in Admin Activity or `operation-diagnostics-read`; the latter is subject to current Target/actor/client authorization.

The HTTP transport reuses the shared Gateway DNS/public-IP egress policy, DNS pinning, real TLS verification, redirect rejection, no arbitrary authentication headers, bounded response collection and structured diagnostic/error reporting. A docs URL cannot select the execution endpoint or grant permissions. All returned OpenAPI content is untrusted input.

Server-configurable memory budgets (bounded further by SafeHttpClient's existing absolute ceiling) are:

- `GATEWAY_API_DOCUMENT_MAX_BYTES` — default 2 MiB for OpenAPI YAML/JSON descriptions
- `GATEWAY_API_RESPONSE_MAX_BYTES` — default 1 MiB for ordinary JSON API responses
- Existing Gateway HTTP connect/request timeouts and host memory/server request limits still apply

These are bounded *response buffers*, not arbitrary API version restrictions. Large binary/object transfers need a separately designed streaming/transfer interface rather than returning an unbounded object in one MCP tool result.

## Documented product/API coverage and remaining protocol boundaries

A 2026-11-17 read-only audit fetched the public ArvanCloud OpenAPI documents for CDN 4.0, IaaS 3 and 1, Object Storage management, Edge, CaaS 1.25, VOD 2, Live 2 and Video Ads 2 directly from `https://www.arvancloud.ir/api-docs/`. Together those specific snapshots describe 969 operations; this is **not** an authenticated interoperability claim or a timeless inventory. It is not a hardcoded endpoint allowlist.

- Compatible machine-user `Apikey` REST/JSON and provider-defined textual requests work through one fixed registered Target origin each, including region/version-specific roots configured by the Owner.
- `multipart/form-data` fields and inline file bytes cover the documented small multipart request *shape* (CDN DNS import, custom pages and certificates, Live watermarks, VOD thumbnail/subtitle/audio track). Actual service acceptance and sufficiently large-file transfer are unverified; sensitive key/certificate uploads require a separate approved private-file path.
- CaaS/Kubernetes content types such as `application/apply-patch+yaml`, `application/json-patch+json`, `application/merge-patch+json`, and `application/strategic-merge-patch+json` can be sent without special endpoint branches.
- Published Swagger 2 descriptions for IaaS v1 and VOD also include TUS resumable-upload endpoints requiring `tus-resumable`, `upload-length`, `upload-offset`, and other protocol headers and binary/chunked transfers. These **are not fully supported** by the generic single-request API tool. Do not relax credential/header ownership or redirect restrictions to simulate TUS; use an explicit reviewed upload workflow when implementing it.
- S3 object operations remain **outside** the machine-user REST connector: S3 requires a separate Access Key/Secret Key, canonical SigV4 signing and a file/stream transport. Do not reuse an Arvan Machine User key for S3 or claim S3 CRUD, multipart S3 upload, object download or presigning is covered.
- Some provider upload workflows return another destination origin or require resumable/binary streaming. They remain unverified and must not bypass registered-origin, secret, ACL or redirect policies. A new protocol/authentication boundary merits a reviewed connector rather than a hidden unrestricted proxy.

### API root and relative path composition

The configured API base must be the **exact base URL** for the chosen product/region/version, without duplicating the path prefix already contained in each operation. These are **examples derived from published spec servers**, not an allowlist or a live authentication guarantee:

| Published API document | Example Target API base | Example request path |
| --- | --- | --- |
| CDN 4.0 | `https://napi.arvancloud.ir/cdn/4.0` | `/domains` |
| IaaS 3.0 (region-specific) | `https://ecc.REGION.arvanapis.ir/v3` (replace REGION with an actual published/approved region host) | `/availability-zones` |
| IaaS 1.0 | `https://napi.arvancloud.ir/ecc/v1` | `/dedicated-servers/available-servers` |
| Object Storage management 1.0 | `https://storage.arvanapis.ir` | `/v1/access-points` |
| Edge Computing 1.0 | `https://napi.arvancloud.ir/ec/v1` | `/edge-computes` |
| CaaS 1.25 (zone-specific) | `https://napi.arvancloud.ir/caas/v2/zones/ir-tbz-sh1` | `/api/v1/namespaces/example/configmaps` |
| VOD 2.0 | `https://napi.arvancloud.ir/vod/2.0` | `/analytics/play-count` |
| Live 2.0 | `https://napi.arvancloud.ir/live/2.0` | `/analytics/play-count` |
| Video Ads 2.0 | `https://napi.arvancloud.ir/vads/2.0` | `/campaigns/{campaign}/ads` |

For example, Object Storage management describes endpoints beginning `/v1` beneath `https://storage.arvanapis.ir`; entering `https://storage.arvanapis.ir/v1` as the base and then sending `/v1/access-points` would incorrectly duplicate `/v1/v1`. A provider spec may advertise alternate environments; **the Gateway never automatically follows spec-advertised servers, switches regions or sends credentials to a new origin**.

## Reuse in later connectors

`App\Infrastructure\Http\Api\ApiHttpTransport` is the shared fixed-base URL, safe relative path, JSON REST request substrate.

`App\Infrastructure\Http\Api\OpenApiOperationCatalog` is a pure generic JSON/YAML OpenAPI catalog reader; no keys, roles, network or provider-specific code.

The `arvancloud` adapter owns its Machine User credential format, connection verification, Target-specific lifecycle and gateway permissions. Another REST provider should reuse these narrow primitives behind its **own registered connector and identity boundary**. Do not introduce a second ACL/credential database or reuse Arvan's API key in another connector. The existing downstream stateless MCP transport is a separate protocol and does not automatically enroll arbitrary MCP Targets.

## Acceptance and limitations

Feature validation requires: unit/catalog tests; registered Target/credential/permission/URL transport tests with no real provider writes; Admin form/visibility tests; WordPress/SSH regression tests; exact-head CI; independent review. A real Arvan account and API key are **not** present in CI. Only a production-target Owner with an appropriately scoped Machine User can do a final live *read-only* authentication acceptance, followed by explicitly authorized writes.

Source implementation [#310](https://github.com/AChWorks/mcp-gateway/issues/310) and **installed v2.7.3 Owner-confirmed** HEAD redirect/authenticated read-only GET acceptance [#321](https://github.com/AChWorks/mcp-gateway/issues/321) are **closed**. Those v2 observations do **not** establish provider connectivity on an unreleased or newly installed v3; repeat only the needed authorized read-only verification during v3 acceptance [#330](https://github.com/AChWorks/mcp-gateway/issues/330).
